package com.hydra.firewall.vpn

import com.hydra.firewall.tr

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Process
import android.util.Log
import java.net.InetAddress
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedDeque

/**
 * Performance-oriented diagnostic logger.
 *
 * NORMAL is intentionally quiet in the packet hot path. DEBUG preserves the
 * detailed per-event diagnostics used during development.
 */
object DiagnosticLogger {
    private const val TAG = "FirewallDiagnostic"
    private const val MAX_BUFFERED_LINES = 500
    private const val DATA_LOG_INTERVAL_MS = 1000L
    private const val AGGREGATE_CLEANUP_MS = 10_000L

    enum class Level { OFF, ERROR, NORMAL, DEBUG }

    @Volatile
    private var level: Level = Level.NORMAL

    private val buffer = ConcurrentLinkedDeque<String>()
    private val lastDataLogAt = ConcurrentHashMap<FlowKey, Long>()
    private val suppressedDataCount = ConcurrentHashMap<FlowKey, Long>()
    private val lastCleanupAt = java.util.concurrent.atomic.AtomicLong(0L)
    private val timeFormat = SimpleDateFormat("HH:mm:ss.SSS", Locale.US)

    private var appContext: Context? = null

    private data class FlowKey(
        val uid: Int,
        val protocol: String,
        val src: String,
        val dst: String
    )

    fun init(context: Context) {
        appContext = context.applicationContext
        startFileWriter()
    }

    fun setLevel(newLevel: Level) { level = newLevel }
    fun getLevel(): Level = level

    fun logTcpSyn(key: SessionKey, resolution: UidResolver.Resolution, mss: Int?, windowScale: Int?, window: Int) {
        if (!enabled(Level.NORMAL)) return
        val text = if (resolution.uid == Process.INVALID_UID) {
            "TCP SYN | uid=INVALID | src=${formatAddr(key.srcAddr, key.srcPort)} | dst=${formatAddr(key.dstAddr, key.dstPort)} | uid_resolution=FAILED | resolver=${resolution.resolvedVia}"
        } else {
            "TCP SYN | uid=${resolution.uid} | pkg=${resolution.packageName ?: "unknown"} | src=${formatAddr(key.srcAddr, key.srcPort)} | dst=${formatAddr(key.dstAddr, key.dstPort)} | mss=${mss ?: "-"} | ws=${windowScale ?: "-"} | win=$window | resolver=${resolution.resolvedVia}"
        }
        emit(text, Level.NORMAL)
    }

    fun logUdpFirstSeen(key: SessionKey, resolution: UidResolver.Resolution, payloadLength: Int) {
        ConnectionHistory.add(resolution.uid, resolution.packageName, "UDP", FirewallVpnService.currentNetworkKind, formatAddr(key.srcAddr, key.srcPort), formatAddr(key.dstAddr, key.dstPort), true, "FIRST-SEEN")
        if (!enabled(Level.NORMAL)) return
        val text = if (resolution.uid == Process.INVALID_UID) {
            "UDP FIRST-SEEN | uid=INVALID | src=${formatAddr(key.srcAddr, key.srcPort)} | dst=${formatAddr(key.dstAddr, key.dstPort)} | uid_resolution=FAILED | resolver=${resolution.resolvedVia}"
        } else {
            "UDP FIRST-SEEN | uid=${resolution.uid} | pkg=${resolution.packageName ?: "unknown"} | src=${formatAddr(key.srcAddr, key.srcPort)} | dst=${formatAddr(key.dstAddr, key.dstPort)} | len=$payloadLength | resolver=${resolution.resolvedVia}"
        }
        emit(text, Level.NORMAL)
    }

    fun logIpv6Unsupported(count: Long) {
        if (!enabled(Level.NORMAL) || count % 50 != 1L) return
        val context = appContext
        val label = context?.let { tr(it, "ipv6_unavailable") } ?: "CONEXIÓN IPv6 NO DISPONIBLE"
        emit("$label | total_seen=$count", Level.NORMAL)
    }

    fun logIcmpv6(type: Int, code: Int, source: InetAddress, destination: InetAddress) {
        if (!enabled(Level.DEBUG)) return
        emit("ICMPV6 | type=$type | code=$code | src=${source.hostAddress} | dst=${destination.hostAddress}", Level.DEBUG)
    }

    fun logServiceEvent(message: String) {
        if (isRepetitivePolicyEvent(message) && isThrottled(message)) return
        emit(message, Level.NORMAL)
    }

    // FIX119: APP_POLICY_DECISION / ADVANCED_RULE_MATCH / DNS_* se emiten por paquete o por consulta;
    // limitar mensajes identicos a 1 cada 5 s evita inundar el log.
    private val lastRepetitiveLogAt = ConcurrentHashMap<String, Long>()

    private fun isRepetitivePolicyEvent(message: String): Boolean =
        message.startsWith("APP_POLICY_DECISION") ||
            message.startsWith("ADVANCED_RULE_MATCH") ||
            message.startsWith("DNS_QUERY") ||
            message.startsWith("DNS_RESPONSE")

    private fun isThrottled(message: String): Boolean {
        val now = System.currentTimeMillis()
        val previous = lastRepetitiveLogAt[message]
        if (previous != null && now - previous < 5_000L) return true
        if (lastRepetitiveLogAt.size > 512) lastRepetitiveLogAt.clear()
        lastRepetitiveLogAt[message] = now
        return false
    }

    fun logTcpOpen(key: SessionKey, uid: Int, packageName: String?) {
        ConnectionHistory.add(uid, packageName, "TCP", FirewallVpnService.currentNetworkKind, formatAddr(key.srcAddr, key.srcPort), formatAddr(key.dstAddr, key.dstPort), true, "OPEN")
        if (!enabled(Level.NORMAL)) return
        emit("TCP OPEN | uid=${uidLabel(uid)} | pkg=${packageName ?: "unknown"} | src=${formatAddr(key.srcAddr, key.srcPort)} | dst=${formatAddr(key.dstAddr, key.dstPort)}", Level.NORMAL)
    }

    fun logTcpRuntime(key: SessionKey, uid: Int, packageName: String?, event: String) {
        val important = !isDataEvent(event) || enabled(Level.DEBUG)
        if (!important) return
        emit("TCP $event | uid=${uidLabel(uid)} | pkg=${packageName ?: "unknown"} | src=${formatAddr(key.srcAddr, key.srcPort)} | dst=${formatAddr(key.dstAddr, key.dstPort)}", Level.NORMAL)
    }

    fun logTcpData(key: SessionKey, uid: Int, packageName: String?, event: String, bytes: Int) {
        aggregateData(key, uid, "TCP", event, bytes)
    }

    fun logUdpRuntime(key: SessionKey, uid: Int, packageName: String?, event: String) {
        if (isDataEvent(event)) {
            if (enabled(Level.DEBUG)) {
                emit("UDP $event | uid=${uidLabel(uid)} | pkg=${packageName ?: "unknown"} | src=${formatAddr(key.srcAddr, key.srcPort)} | dst=${formatAddr(key.dstAddr, key.dstPort)}", Level.DEBUG)
            } else {
                aggregateData(key, uid, "UDP", event.substringBefore(' '))
            }
            return
        }
        if (!enabled(Level.NORMAL)) return
        emit("UDP $event | uid=${uidLabel(uid)} | pkg=${packageName ?: "unknown"} | src=${formatAddr(key.srcAddr, key.srcPort)} | dst=${formatAddr(key.dstAddr, key.dstPort)}", Level.NORMAL)
    }

    fun logUdpData(key: SessionKey, uid: Int, packageName: String?, event: String, bytes: Int) {
        aggregateData(key, uid, "UDP", event, bytes)
    }

    fun logPolicyBlocked(key: SessionKey, uid: Int, packageName: String?, network: NetworkKind, protocolLabel: String, blockedBytes: Int = key.totalPacketBytesEstimate()) {
        TrafficStatsStore.recordBlocked(uid, packageName, blockedBytes)
        ConnectionHistory.add(uid, packageName, protocolLabel, network, formatAddr(key.srcAddr, key.srcPort), formatAddr(key.dstAddr, key.dstPort), false, "BLOCKED")
        if (!enabled(Level.NORMAL)) return

        val flow = FlowKey(uid, protocolLabel, formatAddr(key.srcAddr, key.srcPort), formatAddr(key.dstAddr, key.dstPort))
        val now = System.currentTimeMillis()
        val previous = lastDataLogAt[flow]
        if (previous != null && now - previous < DATA_LOG_INTERVAL_MS && !enabled(Level.DEBUG)) {
            suppressedDataCount.merge(flow, 1L, Long::plus)
            cleanupIfNeeded(now)
            return
        }
        lastDataLogAt[flow] = now
        val suppressed = suppressedDataCount.remove(flow) ?: 0L
        val suffix = if (suppressed > 0) " | repeated=$suppressed" else ""
        emit("$protocolLabel BLOCKED | uid=${uidLabel(uid)} | pkg=${packageName ?: "unknown"} | network=${network.displayName} | src=${formatAddr(key.srcAddr, key.srcPort)} | dst=${formatAddr(key.dstAddr, key.dstPort)}$suffix", Level.NORMAL)
    }

    private fun aggregateData(key: SessionKey, uid: Int, protocol: String, event: String, bytes: Int = 0) {
        val src = formatAddr(key.srcAddr, key.srcPort)
        val dst = formatAddr(key.dstAddr, key.dstPort)
        if (level == Level.DEBUG) {
            emit("$protocol $event | uid=${uidLabel(uid)} | src=$src | dst=$dst | bytes=$bytes", Level.DEBUG)
            return
        }
        if (!enabled(Level.NORMAL)) return
        val flow = FlowKey(uid, protocol, src, dst)
        val now = System.currentTimeMillis()
        val previous = lastDataLogAt[flow]
        val count = suppressedDataCount.merge(flow, 1L, Long::plus) ?: 1L
        if (previous == null || now - previous >= DATA_LOG_INTERVAL_MS) {
            lastDataLogAt[flow] = now
            suppressedDataCount[flow] = 0L
            emit("$protocol $event | uid=${uidLabel(uid)} | src=$src | dst=$dst | packets=$count", Level.NORMAL)
        }
        cleanupIfNeeded(now)
    }

    private fun cleanupIfNeeded(now: Long) {
        val last = lastCleanupAt.get()
        if (now - last < AGGREGATE_CLEANUP_MS || !lastCleanupAt.compareAndSet(last, now)) return
        val cutoff = now - DATA_LOG_INTERVAL_MS * 10
        for ((key, value) in lastDataLogAt) {
            if (value < cutoff) lastDataLogAt.remove(key, value)
        }
        for (key in suppressedDataCount.keys) {
            if (!lastDataLogAt.containsKey(key)) suppressedDataCount.remove(key)
        }
    }

    private fun isDataEvent(event: String): Boolean =
        event.startsWith("C2S_DATA") || event.startsWith("S2C_DATA") || event.startsWith("QUIC/UDP DATA")

    private fun uidLabel(uid: Int) = if (uid == Process.INVALID_UID) "INVALID" else uid.toString()
    private fun formatAddr(addr: InetAddress, port: Int): String {
        val host = addr.hostAddress ?: "?"
        return if (host.contains(':')) "[$host]:$port" else "$host:$port"
    }
    private fun SessionKey.totalPacketBytesEstimate(): Int = 40 + if (protocol == UidResolver.PROTOCOL_UDP) 8 else 20

    private fun enabled(required: Level): Boolean = level != Level.OFF && level.ordinal >= required.ordinal

    private fun emit(message: String, minimum: Level) {
        if (!enabled(minimum)) return
        val timestamp = synchronized(timeFormat) { timeFormat.format(System.currentTimeMillis()) }
        val block = "[$timestamp] $message"
        when (level) {
            Level.DEBUG, Level.NORMAL -> Log.i(TAG, message)
            Level.ERROR -> Log.e(TAG, message)
            Level.OFF -> return
        }
        buffer.addLast(block)
        while (buffer.size > MAX_BUFFERED_LINES) buffer.pollFirst()
        fileQueue.offer(block)
    }

    // ---- FIX119: log en archivo para leer por ADB (sin UI) ----
    // adb pull /sdcard/Android/data/com.hydraroot.firewall/files/hydra-diagnostic.log
    private const val LOG_FILE_NAME = "hydra-diagnostic.log"
    private const val MAX_LOG_FILE_BYTES = 3L * 1024 * 1024
    private val fileQueue = java.util.concurrent.LinkedBlockingQueue<String>(20_000)
    @Volatile private var fileWriterStarted = false

    @Synchronized
    private fun startFileWriter() {
        if (fileWriterStarted) return
        val ctx = appContext ?: return
        fileWriterStarted = true
        val dir = ctx.getExternalFilesDir(null) ?: ctx.filesDir
        Thread({
            val file = java.io.File(dir, LOG_FILE_NAME)
            var writer: java.io.BufferedWriter? = null
            val batch = ArrayList<String>(512)
            while (true) {
                try {
                    batch.clear()
                    batch.add(fileQueue.take())
                    fileQueue.drainTo(batch, 511)
                    // Reabrir si el archivo fue borrado por ADB o superó el tope (rotación a .1).
                    if (writer != null && (!file.exists() || file.length() > MAX_LOG_FILE_BYTES)) {
                        runCatching { writer?.close() }
                        writer = null
                        if (file.exists()) file.renameTo(java.io.File(dir, "$LOG_FILE_NAME.1"))
                    }
                    if (writer == null) {
                        if (file.exists() && file.length() > MAX_LOG_FILE_BYTES) {
                            file.renameTo(java.io.File(dir, "$LOG_FILE_NAME.1"))
                        }
                        val opened = java.io.BufferedWriter(java.io.FileWriter(file, true))
                        writer = opened
                        opened.write("---- log abierto ${com.hydra.firewall.BuildConfig.VERSION_NAME} sdk=${android.os.Build.VERSION.SDK_INT} ----\n")
                    }
                    val out = writer!!
                    for (line in batch) { out.write(line); out.write("\n") }
                    out.flush()
                } catch (e: InterruptedException) {
                    break
                } catch (e: Exception) {
                    runCatching { writer?.close() }
                    writer = null
                    try { Thread.sleep(2_000L) } catch (_: InterruptedException) { break }
                }
            }
        }, "HydraLogWriter").apply { isDaemon = true; priority = Thread.MIN_PRIORITY; start() }
    }

    fun getBufferedLines(): List<String> = buffer.toList()
    fun clearBuffer() = buffer.clear()
}
