package com.hydra.firewall

import android.app.ActivityManager
import android.content.Context
import android.content.pm.PackageManager

/** Installed packages that share the same Android UID, including their labels and icons. */
data class UidPackageEntry(
    val packageName: String,
    val label: String,
    val icon: android.graphics.drawable.Drawable?
)

fun loadUidPackages(context: Context, uid: Int, maxPackages: Int = 12): List<UidPackageEntry> {
    val pm = context.applicationContext.packageManager
    val packages = runCatching { pm.getPackagesForUid(uid)?.toList().orEmpty() }.getOrDefault(emptyList())
    return packages
        .distinct()
        .sorted()
        .take(maxPackages)
        .mapNotNull { pkg ->
            runCatching {
                val info = pm.getApplicationInfo(pkg, 0)
                UidPackageEntry(
                    packageName = pkg,
                    label = pm.getApplicationLabel(info).toString(),
                    icon = pm.getApplicationIcon(info)
                )
            }.getOrNull()
        }
}

/** Declared Android permissions grouped by Android permission group. */
data class AppPermissionGroup(
    val label: String,
    val permissions: List<String>
)

data class UidPermissionPackage(
    val packageName: String,
    val label: String,
    val groups: List<AppPermissionGroup>
)

fun loadAppPermissionGroups(context: Context, packageName: String, maxGroups: Int = 12, maxPermissionsPerGroup: Int = 12): List<AppPermissionGroup> {
    val pm = context.applicationContext.packageManager
    return loadPermissionGroupsForPackage(context, pm, packageName, maxGroups, maxPermissionsPerGroup)
}

/** Aggregates permissions for every package sharing the same UID, preserving package identity. */
fun loadUidPermissionGroups(
    context: Context,
    uid: Int,
    maxPackages: Int = 12,
    maxGroupsPerPackage: Int = 10,
    maxPermissionsPerGroup: Int = 10
): List<UidPermissionPackage> {
    val pm = context.applicationContext.packageManager
    val packages = runCatching { pm.getPackagesForUid(uid)?.toList().orEmpty() }
        .getOrDefault(emptyList())
        .distinct()
        .sorted()
        .take(maxPackages)
    return packages.mapNotNull { pkg ->
        runCatching {
            val info = pm.getApplicationInfo(pkg, 0)
            UidPermissionPackage(
                packageName = pkg,
                label = pm.getApplicationLabel(info).toString(),
                groups = loadPermissionGroupsForPackage(context, pm, pkg, maxGroupsPerPackage, maxPermissionsPerGroup)
            )
        }.getOrNull()
    }
}

private fun loadPermissionGroupsForPackage(
    context: Context,
    pm: PackageManager,
    packageName: String,
    maxGroups: Int,
    maxPermissionsPerGroup: Int
): List<AppPermissionGroup> {
    val requested = runCatching {
        pm.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS).requestedPermissions?.toList().orEmpty()
    }.getOrDefault(emptyList())

    if (requested.isEmpty()) return emptyList()

    val groups = linkedMapOf<String, MutableList<String>>()
    requested.forEach { permission ->
        val groupKey = runCatching {
            val info = pm.getPermissionInfo(permission, 0)
            info.group?.takeIf { it.isNotBlank() } ?: "OTHER"
        }.getOrDefault("OTHER")
        groups.getOrPut(groupKey) { mutableListOf() }.add(permission)
    }

    val english = AppSettings(context).language.isEnglish()
    return groups.entries
        .sortedWith(compareBy({ if (it.key == "OTHER") 1 else 0 }, { it.key }))
        .take(maxGroups)
        .map { (groupName, permissions) ->
            val label = if (groupName == "OTHER") {
                if (english) "Other / ungrouped" else "Otros / sin grupo"
            } else {
                runCatching {
                    pm.getPermissionGroupInfo(groupName, 0).loadLabel(pm).toString()
                }.getOrElse { groupName.substringAfterLast('.') }
            }
            AppPermissionGroup(
                label = label,
                permissions = permissions.distinct().sorted().take(maxPermissionsPerGroup)
            )
        }
}

data class RunningProcessInfo(
    val processName: String,
    val pid: Int,
    val importance: Int
)

/** Best-effort process view for Android 7+: this is process/PID information, not an OS thread id. */
fun loadRunningProcesses(context: Context, uid: Int, maxProcesses: Int = 8): List<RunningProcessInfo> {
    val am = context.applicationContext.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager ?: return emptyList()
    return runCatching {
        am.runningAppProcesses
            .orEmpty()
            .filter { it.uid == uid }
            .distinctBy { "${it.processName}:${it.pid}" }
            .sortedBy { it.processName }
            .take(maxProcesses)
            .map { RunningProcessInfo(it.processName ?: "?", it.pid, it.importance) }
    }.getOrDefault(emptyList())
}
