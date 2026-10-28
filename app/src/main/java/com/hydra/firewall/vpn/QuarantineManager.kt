package com.hydra.firewall.vpn

import android.content.Context
import android.content.pm.PackageManager
import com.hydra.firewall.security.SecurityEngine
import com.hydra.firewall.security.SecurityEventStore
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

class QuarantineManager(context: Context) {
    private val appContext = context.applicationContext
    private val prefs = appContext.getSharedPreferences("quarantine_manager", Context.MODE_PRIVATE)
    private val fmt = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US)

    data class PendingEntry(
        val packageName: String, val uid: Int, val label: String, val installedAt: String,
        val riskLevel: String = "UNKNOWN", val riskScore: Int = 0, val sharedUidPackages: List<String> = emptyList()
    )

    var enabled: Boolean
        get() = prefs.getBoolean(KEY_ENABLED, false)
        set(value) { prefs.edit().putBoolean(KEY_ENABLED, value).apply() }

    fun syncOnStartup(context: Context) {
        val pm = context.packageManager
        val current = runCatching { pm.getInstalledApplications(PackageManager.GET_META_DATA).map { it.packageName }.toSet() }.getOrDefault(emptySet())
        if (!prefs.getBoolean(KEY_PRIMED, false)) {
            prefs.edit().putStringSet(KEY_KNOWN, current).putBoolean(KEY_PRIMED, true).apply(); return
        }
        val known = prefs.getStringSet(KEY_KNOWN, emptySet()).orEmpty()
        // Migrate any still-pending quarantine entries created by older builds so
        // their BLOCK/BLOCK rule does not masquerade as a user decision.
        val migratedRuleStore = RuleStore(context)
        readEntries().forEach { pending ->
            if (pending.uid >= android.os.Process.FIRST_APPLICATION_UID) {
                migratedRuleStore.setQuarantineDefault(pending.uid)
            }
        }

        val newlyAppeared = current - known - context.packageName
        if (newlyAppeared.isEmpty()) return
        if (!enabled) { prefs.edit().putStringSet(KEY_KNOWN, current).apply(); return }
        newlyAppeared.forEach { onPackageAdded(context, it) }
    }

    fun onPackageAdded(context: Context, packageName: String) {
        if (!enabled || packageName == context.packageName) return
        val known = prefs.getStringSet(KEY_KNOWN, emptySet()).orEmpty()
        if (packageName in known) return
        val pm = context.packageManager
        val ai = runCatching { pm.getApplicationInfo(packageName, 0) }.getOrNull() ?: return
        val uid = ai.uid
        val label = runCatching { ai.loadLabel(pm).toString() }.getOrDefault(packageName)
        val sharedPackages = runCatching { pm.getPackagesForUid(uid)?.filter { it != packageName }.orEmpty() }.getOrDefault(emptyList())
        val riskLevel = "SCANNING"
        val riskScore = 0

        if (sharedPackages.isEmpty()) {
            RuleStore(context).setQuarantineDefault(uid)
        } else {
            SecurityEventStore.record(context, "QUARANTINE_LIMIT", "Shared UID not auto-blocked", "$packageName comparte UID $uid con ${sharedPackages.joinToString()}; no se aplicó bloqueo automático para evitar afectar otras apps.", com.hydra.firewall.security.Severity.MEDIUM)
        }

        val entries = readEntries().filterNot { it.packageName == packageName }.toMutableList()
        entries += PendingEntry(packageName, uid, label, fmt.format(Date()), riskLevel, riskScore, sharedPackages)
        writeEntries(entries)
        prefs.edit().putStringSet(KEY_KNOWN, known + packageName).apply()

        // APK parsing can be expensive. Never do it on the BroadcastReceiver main thread.
        SCAN_EXECUTOR.execute {
            val report = runCatching { SecurityEngine(context).scanInstalledPackage(packageName) }.getOrNull()
            if (report != null) {
                updateRisk(packageName, report.risk.level.name, report.risk.score)
            }
        }
    }

    private fun updateRisk(packageName: String, riskLevel: String, riskScore: Int) {
        val updated = readEntries().map { if (it.packageName == packageName) it.copy(riskLevel = riskLevel, riskScore = riskScore) else it }
        writeEntries(updated)
    }

    fun onPackageRemoved(packageName: String) {
        writeEntries(readEntries().filterNot { it.packageName == packageName })
        val known = prefs.getStringSet(KEY_KNOWN, emptySet()).orEmpty() - packageName
        prefs.edit().putStringSet(KEY_KNOWN, known).apply()
    }

    fun pendingEntries(): List<PendingEntry> = readEntries().sortedByDescending { it.installedAt }

    fun review(context: Context, packageName: String, uid: Int, allowWifi: Boolean, allowMobile: Boolean) {
        val packages = runCatching { context.packageManager.getPackagesForUid(uid)?.filter { it != packageName }.orEmpty() }.getOrDefault(emptyList())
        if (packages.isEmpty()) {
            val rs = RuleStore(context)
            rs.setWifiAllowed(uid, allowWifi); rs.setMobileAllowed(uid, allowMobile)
        } else {
            SecurityEventStore.record(context, "QUARANTINE_SHARED_UID", "Manual review with shared UID", "No se cambió el UID $uid porque también pertenece a ${packages.joinToString()}.", com.hydra.firewall.security.Severity.MEDIUM)
        }
        writeEntries(readEntries().filterNot { it.packageName == packageName })
    }

    private fun readEntries(): List<PendingEntry> {
        val raw = prefs.getString(KEY_PENDING_JSON, null)
        if (raw != null) return runCatching {
            val a = JSONArray(raw)
            buildList { for (i in 0 until a.length()) { val o=a.getJSONObject(i); add(PendingEntry(o.getString("package"),o.getInt("uid"),o.getString("label"),o.getString("installedAt"),o.optString("riskLevel","UNKNOWN"),o.optInt("riskScore",0),o.optJSONArray("sharedUid")?.let { arr -> (0 until arr.length()).map { j -> arr.getString(j) } }.orEmpty())) } }
        }.getOrDefault(emptyList())
        // Migrate the old pipe-delimited format once.
        return prefs.getStringSet(KEY_PENDING_OLD, emptySet()).orEmpty().mapNotNull { line ->
            val parts=line.split("|", limit=4); if(parts.size!=4) null else PendingEntry(parts[0],parts[1].toIntOrNull()?:return@mapNotNull null,parts[2],parts[3])
        }
    }

    private fun writeEntries(entries: List<PendingEntry>) {
        val a = JSONArray()
        entries.take(300).forEach { e ->
            a.put(JSONObject().apply {
                put("package", e.packageName); put("uid", e.uid); put("label", e.label.take(500)); put("installedAt", e.installedAt)
                put("riskLevel", e.riskLevel); put("riskScore", e.riskScore); put("sharedUid", JSONArray(e.sharedUidPackages))
            })
        }
        prefs.edit().putString(KEY_PENDING_JSON, a.toString()).remove(KEY_PENDING_OLD).apply()
    }

    companion object {
        private val SCAN_EXECUTOR: ExecutorService = Executors.newSingleThreadExecutor { r -> Thread(r, "Hydra-QuarantineScan") }
        private const val KEY_ENABLED = "enabled"
        private const val KEY_PRIMED = "primed"
        private const val KEY_KNOWN = "known_packages"
        private const val KEY_PENDING_JSON = "pending_entries_json"
        private const val KEY_PENDING_OLD = "pending_entries"
    }
}
