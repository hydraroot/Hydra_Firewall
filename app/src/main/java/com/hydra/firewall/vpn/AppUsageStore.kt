package com.hydra.firewall.vpn

import android.content.Context
import android.content.pm.ApplicationInfo

/** Lightweight user-facing app preferences. Uses SharedPreferences only for small sets. */
class AppFavoritesStore(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences("hydra_app_prefs", Context.MODE_PRIVATE)
    var favoriteUids: Set<Int>
        get() = prefs.getStringSet("favorites", emptySet())?.mapNotNull { it.toIntOrNull() }?.toSet() ?: emptySet()
        set(value) { prefs.edit().putStringSet("favorites", value.map { it.toString() }.toSet()).apply() }

    fun isFavorite(uid: Int): Boolean = uid in favoriteUids
    fun toggle(uid: Int) {
        val next = favoriteUids.toMutableSet()
        if (!next.add(uid)) next.remove(uid)
        favoriteUids = next
    }
}

/**
 * User-selected essential UIDs plus a conservative built-in set of Android
 * components that are commonly required for basic connectivity.
 *
 * Automatic essential status is intentionally narrower than "all system apps".
 * A system application is only auto-essential when the UID is a core Android
 * service UID or every package under the UID is a system package and at least
 * one package matches a connectivity/telephony/Google-services role.
 */
class EssentialAppsStore(private val context: Context) {
    private val appContext = context.applicationContext
    private val prefs = appContext.getSharedPreferences("hydra_app_prefs", Context.MODE_PRIVATE)

    var uids: Set<Int>
        get() = prefs.getStringSet("essential_uids", emptySet())?.mapNotNull { it.toIntOrNull() }?.toSet() ?: emptySet()
        set(value) { prefs.edit().putStringSet("essential_uids", value.map { it.toString() }.toSet()).apply() }

    fun isUserEssential(uid: Int): Boolean = uid in uids

    fun isAutoEssential(uid: Int): Boolean = SystemEssentialAppsDetector.isEssential(appContext, uid)

    fun setUserEssential(uid: Int, enabled: Boolean) {
        val next = uids.toMutableSet()
        if (enabled) next.add(uid) else next.remove(uid)
        uids = next
    }

    fun isEssential(uid: Int): Boolean = isUserEssential(uid) || isAutoEssential(uid)

    fun toggle(uid: Int) {
        val next = uids.toMutableSet()
        if (!next.add(uid)) next.remove(uid)
        uids = next
    }
}

object SystemEssentialAppsDetector {
    // Only these core Android service identities are automatically essential.
    // Ordinary packages, including Google services/apps, must follow the normal
    // first-connection prompt unless the user explicitly selects Essential or
    // enables the optional Apps de confianza policy.
    private const val SYSTEM_UID = 1000
    private const val RADIO_UID = 1001

    fun isEssential(context: Context, uid: Int): Boolean {
        return uid == SYSTEM_UID || uid == RADIO_UID
    }
}
