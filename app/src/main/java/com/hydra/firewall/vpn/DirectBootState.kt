package com.hydra.firewall.vpn

import android.content.Context

object DirectBootState {
    private const val PREFS = "hydra_direct_boot"
    private const val KEY_PENDING = "pending"
    private const val KEY_LAST_LOCKED = "last_locked_boot"

    private fun prefs(context: Context) = context.createDeviceProtectedStorageContext().getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    fun markLockedBoot(context: Context) {
        prefs(context).edit().putBoolean(KEY_PENDING, true).putLong(KEY_LAST_LOCKED, System.currentTimeMillis()).apply()
    }

    fun markUnlocked(context: Context) {
        prefs(context).edit().putBoolean(KEY_PENDING, false).apply()
    }

    fun pending(context: Context): Boolean = prefs(context).getBoolean(KEY_PENDING, false)
    fun lastLockedBoot(context: Context): Long = prefs(context).getLong(KEY_LAST_LOCKED, 0L)
}
