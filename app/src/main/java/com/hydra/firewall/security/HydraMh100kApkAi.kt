package com.hydra.firewall.security

import android.content.Context

import kotlin.math.exp
import kotlin.math.roundToInt

/**
 * Runtime reader for the compact MH-100K APK security model.
 *
 * The model is deliberately a secondary static-analysis signal. It never
 * blocks traffic, quarantines an app, or overrides deterministic signatures.
 */
object HydraMh100kApkAi {
    private const val ASSET = "hydra_apk_ai_mh100k_v2.bin"
    private val MAGIC = byteArrayOf('H'.code.toByte(), 'Y'.code.toByte(), 'D'.code.toByte(), 'R'.code.toByte(), 'A'.code.toByte(), 'A'.code.toByte(), 'I'.code.toByte(), '2'.code.toByte())
    private const val HEADER_BYTES = 20
    private const val ENTRY_BYTES = 16
    private const val EXPECTED_VERSION = 2
    private const val EXPECTED_FEATURES = 2048
    private const val PRESENCE_MODE = 0
    private const val ABSENCE_MODE = 1

    data class Result(
        val score: Int,
        val rawLogit: Double,
        val matchedFeatures: Int,
        val modelFeatureCount: Int,
        val modelVersion: String,
        val extractedFeatureCount: Int
    )

    private data class Model(
        val version: String,
        val hashes: LongArray,
        val knownHashes: HashSet<Long>,
        val weights: FloatArray,
        val modes: ByteArray,
        val intercept: Double
    ) {
        fun isKnown(hash: Long): Boolean = knownHashes.contains(hash)
    }

    @Volatile
    private var model: Model? = null

    @Synchronized
    fun init(context: Context): Boolean {
        if (model != null) return true
        model = runCatching {
            val bytes = context.applicationContext.assets.open(ASSET).use { it.readBytes() }
            parse(bytes)
        }.getOrNull()
        return model != null
    }

    fun isLoaded(): Boolean = model != null

    /**
     * Human-readable reading of the score. On the held-out MH-100K test set, score >= 50 had ~64 % precision
     * (about 1 in 3 flagged apps was legitimate), score >= 90 about 81 % and score >= 95 about 87 %.
     * The score is not a calibrated probability: this label only avoids presenting a mid score as an alarm.
     */
    fun suspicionLabel(score: Int, english: Boolean): String = when {
        score >= 95 -> if (english) "Very high suspicion — review this app" else "Sospecha muy alta: revisá esta app"
        score >= 90 -> if (english) "High suspicion — review this app" else "Sospecha alta: revisá esta app"
        score >= 50 -> if (english) "Weak hint — many legitimate apps score here" else "Indicio débil: muchas apps legítimas puntúan acá"
        else -> if (english) "Low suspicion" else "Sospecha baja"
    }

    fun isKnownFeatureHash(hash: Long): Boolean = model?.isKnown(hash) == true

    fun score(presentFeatureHashes: LongArray): Result? {
        val m = model ?: return null
        return scoreInternal(m, presentFeatureHashes)
    }

    internal fun loadModelForTest(bytes: ByteArray) {
        model = parse(bytes)
    }

    private fun scoreInternal(m: Model, presentFeatureHashes: LongArray): Result {
        val present = HashSet<Long>(presentFeatureHashes.size * 2 + 1)
        presentFeatureHashes.forEach(present::add)
        var logit = m.intercept
        var matched = 0
        for (i in m.hashes.indices) {
            val featurePresent = present.contains(m.hashes[i])
            val activate = if (m.modes[i].toInt() == PRESENCE_MODE) featurePresent else !featurePresent
            if (activate) {
                logit += m.weights[i].toDouble()
                matched++
            }
        }
        // Avoid numerical overflow while preserving the monotonic logistic signal.
        val bounded = logit.coerceIn(-50.0, 50.0)
        val signal = (1.0 / (1.0 + exp(-bounded)))
        val score = (signal * 100.0).roundToInt().coerceIn(0, 100)
        return Result(
            score = score,
            rawLogit = logit,
            matchedFeatures = matched,
            modelFeatureCount = m.hashes.size,
            modelVersion = m.version,
            extractedFeatureCount = present.size
        )
    }

    private fun parse(bytes: ByteArray): Model {
        require(bytes.size >= HEADER_BYTES) { "MH-100K model truncated" }
        require(bytes.copyOfRange(0, MAGIC.size).contentEquals(MAGIC)) { "Invalid MH-100K model magic" }
        val version = u32(bytes, 8)
        val featureCount = u32(bytes, 12)
        require(version == EXPECTED_VERSION) { "Unsupported MH-100K model version: $version" }
        require(featureCount == EXPECTED_FEATURES) { "Unexpected MH-100K feature count: $featureCount" }
        require(bytes.size == HEADER_BYTES + featureCount * ENTRY_BYTES) { "Invalid MH-100K model size" }

        val hashes = LongArray(featureCount)
        val weights = FloatArray(featureCount)
        val modes = ByteArray(featureCount)
        var offset = HEADER_BYTES
        for (i in 0 until featureCount) {
            hashes[i] = u64(bytes, offset)
            weights[i] = float32(bytes, offset + 8)
            modes[i] = bytes[offset + 12]
            require(modes[i].toInt() == PRESENCE_MODE || modes[i].toInt() == ABSENCE_MODE) {
                "Invalid MH-100K feature mode at index $i"
            }
            offset += ENTRY_BYTES
        }
        return Model(
            version = "hydra-apk-ai-mh100k-v2",
            hashes = hashes,
            knownHashes = hashes.toHashSet(),
            weights = weights,
            modes = modes,
            intercept = float32(bytes, 16).toDouble()
        )
    }

    private fun u32(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xFF) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 3].toInt() and 0xFF) shl 24)

    private fun u64(bytes: ByteArray, offset: Int): Long {
        var result = 0L
        for (i in 0 until 8) result = result or ((bytes[offset + i].toLong() and 0xFFL) shl (8 * i))
        return result
    }

    private fun float32(bytes: ByteArray, offset: Int): Float = java.lang.Float.intBitsToFloat(u32(bytes, offset))
}

/**
 * Best-effort static feature extractor compatible with the compact MH-100K
 * runtime vocabulary: manifest permissions/intents plus invoked DEX API calls.
 *
 * It intentionally remains bounded for on-device scanning. A scan may report
 * extractionIncomplete when a DEX is too large or the time budget is reached.
 */
class Mh100kStaticFeatureExtractor {
    data class ExtractionResult(
        val presentFeatureHashes: LongArray,
        val apiCallsObserved: Int,
        val permissionFeaturesObserved: Int,
        val intentFeaturesObserved: Int,
        val dexFilesAnalyzed: Int,
        val extractionIncomplete: Boolean,
        val errors: List<String>
    )

    companion object {
        private const val MAX_DEX_BYTES_PER_FILE = 24L * 1024L * 1024L
        private const val MAX_TOTAL_DEX_BYTES = 48L * 1024L * 1024L
        private const val MAX_EXTRACT_MILLIS = 5_500L
        private const val MANIFEST_LIMIT = 4L * 1024L * 1024L
        private val DEX_NAME = Regex("""classes(\d*)?\.dex""")

        /**
         * Same result as the regex `([A-Z][A-Z0-9_]{2,})$` (the leftmost match that reaches the end of the
         * string) but in linear time. The regex is quadratic on long runs of capital letters/digits
         * (100,000 characters took ~47 s), which let one odd DEX string freeze the whole scan.
         */
        internal fun intentSuffix(text: String): String? {
            val end = text.length
            var runStart = end
            while (runStart > 0) {
                val c = text[runStart - 1]
                if ((c in 'A'..'Z') || (c in '0'..'9') || c == '_') runStart-- else break
            }
            var i = runStart
            while (i < end && text[i] !in 'A'..'Z') i++
            return if (i < end && end - i >= 3) text.substring(i) else null
        }
    }

    fun extract(
        apkFile: java.io.File,
        splitFiles: List<java.io.File> = emptyList(),
        permissions: List<String> = emptyList()
    ): ExtractionResult {
        val startedAt = System.currentTimeMillis()
        val present = LinkedHashSet<Long>()
        val errors = mutableListOf<String>()
        var apiCallsObserved = 0
        var permissionFeaturesObserved = 0
        var intentFeaturesObserved = 0
        var dexFilesAnalyzed = 0
        var incomplete = false
        var totalDexBytes = 0L

        fun recordPermission(permission: String) {
            val short = permission.substringAfterLast('.').trim()
            if (short.isBlank()) return
            val hash = fnv1a64("Permission::$short")
            if (HydraMh100kApkAi.isKnownFeatureHash(hash) && present.add(hash)) permissionFeaturesObserved++
        }

        fun recordIntent(raw: String): Boolean {
            val normalized = raw.trim().substringBefore('\u0000')
            if (normalized.isBlank()) return false
            val suffix = intentSuffix(normalized) ?: return false
            val hash = fnv1a64("Intent::$suffix")
            return HydraMh100kApkAi.isKnownFeatureHash(hash) && present.add(hash)
        }

        if (System.currentTimeMillis() - startedAt < MAX_EXTRACT_MILLIS) {
            runCatching {
                val files = buildList {
                    add(apkFile)
                    addAll(splitFiles.filter { it.isFile && it.canRead() })
                }
                for (file in files) {
                    if (System.currentTimeMillis() - startedAt >= MAX_EXTRACT_MILLIS) {
                        incomplete = true
                        break
                    }
                    java.util.zip.ZipFile(file).use { zip ->
                        if (file == apkFile) {
                            val entry = zip.getEntry("AndroidManifest.xml")
                            if (entry != null && entry.size in 1L..MANIFEST_LIMIT) {
                                val bytes = zip.getInputStream(entry).use { it.readBytes() }
                                extractManifestStrings(bytes).forEach {
                                    if (recordIntent(it)) intentFeaturesObserved++
                                }
                            }
                        }
                        val entries = zip.entries()
                        while (entries.hasMoreElements()) {
                            if (System.currentTimeMillis() - startedAt >= MAX_EXTRACT_MILLIS) {
                                incomplete = true
                                break
                            }
                            val entryDex = entries.nextElement()
                            if (!DEX_NAME.matches(entryDex.name)) continue
                            val size = entryDex.size
                            if (size <= 0L) continue
                            if (size > MAX_DEX_BYTES_PER_FILE || totalDexBytes + size > MAX_TOTAL_DEX_BYTES) {
                                incomplete = true
                                errors += "MH-100K: DEX omitido por límite de tamaño: ${entryDex.name}"
                                continue
                            }
                            val dexBytes = zip.getInputStream(entryDex).use { it.readBytes() }
                            totalDexBytes += dexBytes.size
                            val result = scanDex(
                                dexBytes,
                                present,
                                { raw -> recordIntent(raw) },
                                deadlineMs = startedAt + MAX_EXTRACT_MILLIS
                            )
                            apiCallsObserved += result.apiCallsObserved
                            intentFeaturesObserved += result.newIntentFeatures
                            incomplete = incomplete || result.incomplete
                            dexFilesAnalyzed++
                        }
                    }
                }
            }.onFailure {
                errors += "MH-100K: ${it.message ?: it.javaClass.simpleName}"
                incomplete = true
            }
        } else {
            incomplete = true
        }

        for (permission in permissions) recordPermission(permission)

        val hashes = present.toLongArray()
        return ExtractionResult(
            presentFeatureHashes = hashes,
            apiCallsObserved = apiCallsObserved,
            permissionFeaturesObserved = permissionFeaturesObserved,
            intentFeaturesObserved = intentFeaturesObserved,
            dexFilesAnalyzed = dexFilesAnalyzed,
            extractionIncomplete = incomplete,
            errors = errors.distinct().take(8)
        )
    }

    private data class DexScanResult(
        val apiCallsObserved: Int,
        val newIntentFeatures: Int,
        val incomplete: Boolean
    )

    private fun scanDex(
        bytes: ByteArray,
        present: MutableSet<Long>,
        recordIntent: (String) -> Boolean,
        deadlineMs: Long
    ): DexScanResult {
        val parser = DexParser(bytes)
        if (!parser.isValid()) return DexScanResult(0, 0, true)
        var apiCalls = 0
        var newIntent = 0
        var stringsSeen = 0
        for (value in parser.allStrings()) {
            if ((++stringsSeen and 0x3FF) == 0 && System.currentTimeMillis() >= deadlineMs) {
                return DexScanResult(apiCalls, newIntent, true)
            }
            if (recordIntent(value)) newIntent++
        }
        parser.forEachInvokedMethod(deadlineMs) { feature ->
            apiCalls++
            val hash = fnv1a64("APICall::$feature")
            if (HydraMh100kApkAi.isKnownFeatureHash(hash)) present.add(hash)
        }
        return DexScanResult(apiCalls, newIntent, parser.incomplete)
    }

    private fun extractManifestStrings(bytes: ByteArray): List<String> {
        if (bytes.size < 28) return emptyList()
        return runCatching {
            val chunkType = u16(bytes, 0)
            if (chunkType != 0x0003 && chunkType != 0x0001) return@runCatching emptyList<String>()
            val stringChunk = findStringPool(bytes) ?: return@runCatching emptyList<String>()
            readStringPool(bytes, stringChunk.first, stringChunk.second)
        }.getOrDefault(emptyList())
    }

    private fun findStringPool(bytes: ByteArray): Pair<Int, Int>? {
        if (bytes.size < 8) return null
        var offset = u16(bytes, 2).coerceAtLeast(8)
        var depth = 0
        while (offset + 8 <= bytes.size && depth++ < 64) {
            val type = u16(bytes, offset)
            val headerSize = u16(bytes, offset + 2)
            val size = u32(bytes, offset + 4).toLong() and 0xFFFF_FFFFL
            if (size < headerSize || size > bytes.size - offset) return null
            if (type == 0x0001) return offset to size.toInt()
            offset += size.toInt()
        }
        return null
    }

    private fun readStringPool(bytes: ByteArray, offset: Int, chunkSize: Int): List<String> {
        if (offset + 28 > bytes.size) return emptyList()
        val stringCount = u32(bytes, offset + 8)
        val flags = u32(bytes, offset + 16)
        val stringsStart = u32(bytes, offset + 20)
        val offsetsStart = offset + 28
        if (stringCount <= 0 || stringCount > 100_000) return emptyList()
        if (offsetsStart + stringCount * 4L > bytes.size) return emptyList()
        val out = ArrayList<String>(stringCount)
        val utf8 = (flags and 0x100) != 0
        for (i in 0 until stringCount) {
            val rel = u32(bytes, offsetsStart + i * 4)
            val at = offset + stringsStart + rel
            if (at < offset || at >= offset + chunkSize || at >= bytes.size) continue
            runCatching { decodeStringPoolEntry(bytes, at, utf8) }.getOrNull()?.let(out::add)
        }
        return out
    }

    private fun decodeStringPoolEntry(bytes: ByteArray, at: Int, utf8: Boolean): String {
        return if (utf8) {
            var p = at
            readLength8(bytes, p).also { p = it.second }
            val byteLength = readLength8(bytes, p).also { p = it.second }.first
            val end = (p + byteLength).coerceAtMost(bytes.size)
            String(bytes, p, (end - p).coerceAtLeast(0), Charsets.UTF_8)
        } else {
            var p = at
            val len = readLength16(bytes, p).also { p = it.second }.first
            val end = (p + len * 2).coerceAtMost(bytes.size)
            String(bytes, p, (end - p).coerceAtLeast(0), Charsets.UTF_16LE)
        }
    }

    private fun readLength8(bytes: ByteArray, at: Int): Pair<Int, Int> {
        val first = bytes.getOrNull(at)?.toInt()?.and(0xFF) ?: return 0 to at
        return if ((first and 0x80) == 0) first to at + 1
        else (((first and 0x7F) shl 8) or (bytes.getOrNull(at + 1)?.toInt()?.and(0xFF) ?: 0)) to at + 2
    }

    private fun readLength16(bytes: ByteArray, at: Int): Pair<Int, Int> {
        val first = u16(bytes, at)
        return if ((first and 0x8000) == 0) first to at + 2
        else (((first and 0x7FFF) shl 16) or u16(bytes, at + 2)) to at + 4
    }

    private fun fnv1a64(text: String): Long {
        var hash = 0xcbf29ce484222325UL.toLong()
        text.toByteArray(Charsets.UTF_8).forEach { byte ->
            hash = hash xor (byte.toInt() and 0xFF).toLong()
            hash *= 0x100000001b3L
        }
        return hash
    }

    private fun u16(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xFF) or ((bytes[offset + 1].toInt() and 0xFF) shl 8)

    private fun u32(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xFF) or
            ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
            ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
            ((bytes[offset + 3].toInt() and 0xFF) shl 24)

    private class DexParser(private val bytes: ByteArray) {
        private var timedOut = false

        private companion object {
            /** A DEX string is at most 65,535 UTF-16 units; cap reads so a bad offset cannot scan the whole file per string. */
            const val MAX_STRING_BYTES = 256 * 1024
            /** Total characters read across all strings of one DEX. */
            const val STRING_TOTAL_BUDGET_BYTES = 96L * 1024L * 1024L
        }

        private data class Uleb(val value: Int, val next: Int)

        fun isValid(): Boolean =
            bytes.size >= 112 &&
                bytes[0].toInt() == 'd'.code && bytes[1].toInt() == 'e'.code && bytes[2].toInt() == 'x'.code &&
                bytes[3].toInt() == '\n'.code

        fun allStrings(): Array<String> {
            if (!isValid()) return emptyArray()
            val count = u32(56)
            val off = u32(60)
            if (count <= 0 || count > 500_000 || off < 0 || off.toLong() + count.toLong() * 4L > bytes.size) return emptyArray()
            var budget = STRING_TOTAL_BUDGET_BYTES
            return Array(count) { index ->
                val rel = u32(off + index * 4)
                val at = rel.coerceAtLeast(0)
                if (at >= bytes.size || budget <= 0) "" else readMutf8(at).also { budget -= it.length + 1 }
            }
        }

        fun forEachInvokedMethod(deadlineMs: Long, consumer: (String) -> Unit) {
            if (!isValid()) return
            val strings = allStrings()
            val typeCount = u32(64)
            val typeOff = u32(68)
            val methodCount = u32(88)
            val methodOff = u32(92)
            val classCount = u32(96)
            val classOff = u32(100)
            if (typeCount < 0 || methodCount < 0 || classCount < 0) {
                timedOut = true
                return
            }
            if (!rangeOk(typeOff, typeCount, 4) || !rangeOk(methodOff, methodCount, 8) || !rangeOk(classOff, classCount, 32)) {
                timedOut = true
                return
            }

            val typeDescriptorStringIdx = IntArray(typeCount) { u32(typeOff + it * 4) }
            val methodClassIdx = IntArray(methodCount)
            val methodNameIdx = IntArray(methodCount)
            for (i in 0 until methodCount) {
                val at = methodOff + i * 8
                methodClassIdx[i] = u16(at)
                methodNameIdx[i] = u32(at + 4)
            }

            for (classIndex in 0 until classCount) {
                if (System.currentTimeMillis() >= deadlineMs) {
                    timedOut = true
                    return
                }
                val classAt = classOff + classIndex * 32
                val classDataOff = u32(classAt + 24)
                if (classDataOff == 0) continue
                if (classDataOff < 0 || classDataOff >= bytes.size) {
                    timedOut = true
                    return
                }
                val cursor = intArrayOf(classDataOff)
                val staticFields = readUleb(cursor)
                val instanceFields = readUleb(cursor)
                val directMethods = readUleb(cursor)
                val virtualMethods = readUleb(cursor)
                // Every field/method entry takes at least 2 bytes, so counts larger than the bytes left are
                // corrupt or deliberately malformed (packers). Without this check a bogus count could spin for hours.
                val bytesLeft = (bytes.size - cursor[0]).toLong()
                if (staticFields < 0 || instanceFields < 0 || directMethods < 0 || virtualMethods < 0 ||
                    (staticFields.toLong() + instanceFields.toLong() + directMethods.toLong() + virtualMethods.toLong()) * 2L > bytesLeft) {
                    timedOut = true
                    return
                }
                repeat(staticFields) { readUleb(cursor); readUleb(cursor) }
                repeat(instanceFields) { readUleb(cursor); readUleb(cursor) }
                var methodIndex = 0
                repeat(directMethods + virtualMethods) {
                    methodIndex += readUleb(cursor)
                    if (methodIndex !in methodClassIdx.indices) {
                        timedOut = true
                        return
                    }
                    readUleb(cursor) // access flags
                    val codeOff = readUleb(cursor)
                    if (codeOff == 0) {
                        // Abstract/native method: no code item to scan.
                    } else if (codeOff < 0 || codeOff >= bytes.size) {
                        timedOut = true
                        return
                    } else if (System.currentTimeMillis() < deadlineMs) {
                        scanCodeItem(codeOff, methodClassIdx, methodNameIdx, typeDescriptorStringIdx, strings, deadlineMs, consumer)
                        if (timedOut) return
                    } else {
                        timedOut = true
                        return
                    }
                }
            }
        }

        val incomplete: Boolean get() = timedOut

        private fun scanCodeItem(
            codeOff: Int,
            methodClassIdx: IntArray,
            methodNameIdx: IntArray,
            typeDescriptorStringIdx: IntArray,
            strings: Array<String>,
            deadlineMs: Long,
            consumer: (String) -> Unit
        ) {
            if (codeOff < 0 || codeOff.toLong() + 16L > bytes.size) {
                timedOut = true
                return
            }
            val insnsSize = u32(codeOff + 12)
            val insnsAt = codeOff + 16
            if (insnsSize <= 0 || insnsAt < 0 || insnsSize.toLong() * 2L > bytes.size - insnsAt) {
                timedOut = true
                return
            }
            var pc = 0
            while (pc < insnsSize) {
                if (System.currentTimeMillis() >= deadlineMs) {
                    timedOut = true
                    return
                }
                val unit = u16(insnsAt + pc * 2)
                val opcode = unit and 0xFF
                val payloadSize = when (unit) {
                    0x0100 -> 4 + u16(insnsAt + (pc + 1) * 2) * 2
                    0x0200 -> 2 + u16(insnsAt + (pc + 1) * 2) * 4
                    0x0300 -> {
                        val elementWidth = u16(insnsAt + (pc + 1) * 2)
                        val elementCount = u32(insnsAt + (pc + 2) * 2).toLong() and 0xFFFF_FFFFL
                        4 + ((elementCount * elementWidth + 1) / 2).coerceAtMost(Int.MAX_VALUE.toLong()).toInt()
                    }
                    else -> 0
                }
                if (payloadSize > 0) {
                    pc += payloadSize
                    continue
                }

                if (opcode in 0x6E..0x72 || opcode in 0x74..0x78 || opcode == 0xFA || opcode == 0xFB) {
                    if (pc + 1 < insnsSize) {
                        val methodIndex = u16(insnsAt + (pc + 1) * 2)
                        if (methodIndex in methodClassIdx.indices) {
                            val classIdx = methodClassIdx[methodIndex]
                            val nameIdx = methodNameIdx[methodIndex]
                            if (classIdx in typeDescriptorStringIdx.indices && nameIdx in strings.indices) {
                                val descriptorIdx = typeDescriptorStringIdx[classIdx]
                                if (descriptorIdx in strings.indices) {
                                    val descriptor = strings[descriptorIdx].trimEnd(';')
                                    val name = strings[nameIdx]
                                    if (descriptor.startsWith("L") && name.isNotBlank()) {
                                        consumer("$descriptor.$name()")
                                    }
                                }
                            }
                        }
                    }
                }

                val size = instructionSize(opcode)
                if (size <= 0 || pc + size > insnsSize) {
                    timedOut = true
                    return
                }
                pc += size
            }
        }

        private fun instructionSize(opcode: Int): Int = when {
            opcode == 0x03 || opcode == 0x06 || opcode == 0x09 || opcode == 0x14 || opcode == 0x17 || opcode == 0x1B || opcode in 0x24..0x26 || opcode in 0x2A..0x2C || opcode in 0x6E..0x72 || opcode in 0x74..0x78 || opcode == 0xFC || opcode == 0xFD -> 3
            opcode == 0x18 -> 5
            opcode == 0xFA || opcode == 0xFB -> 4
            opcode == 0x02 || opcode == 0x05 || opcode == 0x08 || opcode == 0x13 || opcode == 0x15 || opcode == 0x16 || opcode == 0x19 || opcode == 0x1A || opcode == 0x1C || opcode == 0x1F || opcode == 0x20 || opcode == 0x22 || opcode == 0x23 || opcode == 0x29 || opcode in 0x2D..0x3D || opcode in 0x44..0x6D || opcode in 0x90..0xAF || opcode in 0xD0..0xE2 || opcode == 0xFE || opcode == 0xFF -> 2
            else -> 1
        }

        private fun rangeOk(offset: Int, count: Int, itemBytes: Int): Boolean =
            offset >= 0 && count >= 0 && offset.toLong() + count.toLong() * itemBytes <= bytes.size

        private fun readUleb(cursor: IntArray): Int {
            var result = 0
            var shift = 0
            while (cursor[0] < bytes.size && shift < 35) {
                val b = bytes[cursor[0]++].toInt() and 0xFF
                result = result or ((b and 0x7F) shl shift)
                if ((b and 0x80) == 0) return result
                shift += 7
            }
            return 0
        }

        private fun readMutf8(offset: Int): String {
            var p = offset
            readUlebAt(p).also { p = it.next }
            val out = java.io.ByteArrayOutputStream()
            val limit = minOf(bytes.size, p + MAX_STRING_BYTES)
            while (p < limit) {
                val b = bytes[p++].toInt() and 0xFF
                if (b == 0) break
                out.write(b)
            }
            return runCatching { String(out.toByteArray(), Charsets.UTF_8) }.getOrDefault("")
        }

        private fun readUlebAt(at: Int): Uleb {
            var p = at
            var result = 0
            var shift = 0
            while (p < bytes.size && shift < 35) {
                val b = bytes[p++].toInt() and 0xFF
                result = result or ((b and 0x7F) shl shift)
                if ((b and 0x80) == 0) break
                shift += 7
            }
            return Uleb(result, p)
        }

        private fun u16(offset: Int): Int =
            if (offset < 0 || offset + 1 >= bytes.size) 0 else (bytes[offset].toInt() and 0xFF) or ((bytes[offset + 1].toInt() and 0xFF) shl 8)

        private fun u32(offset: Int): Int =
            if (offset < 0 || offset + 3 >= bytes.size) 0 else
                (bytes[offset].toInt() and 0xFF) or
                    ((bytes[offset + 1].toInt() and 0xFF) shl 8) or
                    ((bytes[offset + 2].toInt() and 0xFF) shl 16) or
                    ((bytes[offset + 3].toInt() and 0xFF) shl 24)
    }
}
