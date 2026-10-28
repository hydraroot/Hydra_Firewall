package com.hydra.firewall.vpn

import android.content.Context
import android.content.pm.ApplicationInfo
import android.os.Build
import com.hydra.firewall.security.ThreatSignatureStore
import java.net.InetAddress

/**
 * Pegamento con Android de [ConnectionExplainer]: reúne los hechos que ya conoce la app (DNS que resolvió la
 * app, listas de bloqueo, inteligencia de amenazas, origen de instalación) y devuelve las razones.
 * Todo es de SOLO LECTURA: no toca contadores ni reglas, y nunca hace consultas de red (no resuelve DNS).
 */
object ConnectionContext {
    private const val DAY_MS = 24L * 60L * 60L * 1000L
    private val PLAY = setOf("com.android.vending")
    private val OTHER_STORES = setOf(
        "com.amazon.venezia", "com.sec.android.app.samsungapps", "com.huawei.appmarket",
        "com.xiaomi.mipicks", "com.xiaomi.discover", "org.fdroid.fdroid", "org.fdroid.basic",
        "com.heytap.market", "com.oppo.market", "com.vivo.appstore", "com.aurora.store", "com.apkpure.aegon"
    )
    private val FILE_INSTALLERS = setOf(
        "com.google.android.packageinstaller", "com.android.packageinstaller", "com.samsung.android.packageinstaller"
    )

    fun explain(
        context: Context,
        uid: Int,
        packageName: String?,
        destination: String,
        protocol: String,
        allowed: Boolean?,
        firstConnection: Boolean,
        repeatCount: Int = 1,
        max: Int = 6
    ): List<ConnectionExplainer.Reason> = runCatching {
        ConnectionExplainer.explain(facts(context, uid, packageName, destination, protocol, allowed, firstConnection, repeatCount), max)
    }.getOrDefault(emptyList())

    private fun facts(
        context: Context, uid: Int, packageName: String?, destination: String, protocol: String,
        allowed: Boolean?, firstConnection: Boolean, repeatCount: Int
    ): ConnectionExplainer.Facts {
        val ep = ConnectionExplainer.parseEndpoint(destination)
        val host = ep?.host
        val isIp = host != null && ConnectionExplainer.isIpLiteral(host)

        // Dominio: 1) el que la propia app resolvió hace poco; 2) DNS inverso ya en caché. Nunca se resuelve en red.
        var domain: String? = null
        if (host != null) {
            domain = if (isIp) {
                val addr = runCatching { InetAddress.getByName(host.substringBefore('%')) }.getOrNull()
                addr?.let { DnsIpCorrelationStore.lookup(uid, it) } ?: DomainResolver.cached(host)
            } else host
        }

        val blocklisted = domain?.let { DomainBlockStore.matchesWithoutCounting(it) } ?: false

        var threat: String? = null
        if (domain != null) {
            ThreatSignatureStore.matchDomain(context, domain)?.let { threat = describe(it.match.source, it.match.family) }
        }
        if (threat == null && isIp && host != null) {
            ThreatSignatureStore.matchIp(context, host)?.let { threat = describe(it.match.source, it.match.family) }
        }

        val pm = context.packageManager
        val pkg = packageName?.takeIf { it.isNotBlank() } ?: runCatching { pm.getPackagesForUid(uid)?.firstOrNull() }.getOrNull()
        var source = ConnectionExplainer.InstallSource.UNKNOWN
        var installedDays: Long? = null
        var updatedDays: Long? = null
        if (pkg != null) {
            val info = runCatching { pm.getPackageInfo(pkg, 0) }.getOrNull()
            if (info != null) {
                val now = System.currentTimeMillis()
                if (info.firstInstallTime > 0) installedDays = ((now - info.firstInstallTime) / DAY_MS).coerceAtLeast(0L)
                if (info.lastUpdateTime > 0) updatedDays = ((now - info.lastUpdateTime) / DAY_MS).coerceAtLeast(0L)
                val flags = info.applicationInfo?.flags ?: 0
                val isSystem = flags and (ApplicationInfo.FLAG_SYSTEM or ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
                val installer = runCatching {
                    if (Build.VERSION.SDK_INT >= 30) pm.getInstallSourceInfo(pkg).installingPackageName
                    else @Suppress("DEPRECATION") pm.getInstallerPackageName(pkg)
                }.getOrNull()
                source = when {
                    isSystem -> ConnectionExplainer.InstallSource.SYSTEM
                    installer in PLAY -> ConnectionExplainer.InstallSource.PLAY_STORE
                    installer in OTHER_STORES -> ConnectionExplainer.InstallSource.OTHER_STORE
                    installer == null || installer.isEmpty() || installer in FILE_INSTALLERS -> ConnectionExplainer.InstallSource.SIDELOADED
                    else -> ConnectionExplainer.InstallSource.UNKNOWN
                }
            }
        }

        return ConnectionExplainer.Facts(
            destinationHost = host,
            domain = domain,
            port = ep?.port ?: -1,
            protocol = protocol,
            allowed = allowed,
            firstConnection = firstConnection,
            domainOnBlocklist = blocklisted,
            threatDetail = threat,
            installSource = source,
            installedDaysAgo = installedDays,
            updatedDaysAgo = updatedDays,
            repeatCount = repeatCount
        )
    }

    private fun describe(source: String?, family: String?): String =
        listOfNotNull(source?.takeIf { it.isNotBlank() }, family?.takeIf { it.isNotBlank() }).joinToString(" • ").ifBlank { "indicador conocido" }
}
