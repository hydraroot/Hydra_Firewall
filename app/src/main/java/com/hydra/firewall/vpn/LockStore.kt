package com.hydra.firewall.vpn

import android.content.Context
import android.os.Build
import android.util.Base64
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

/**
 * Local HYDRA authentication store.
 *
 * V2 stores a PBKDF2 verifier (HMAC-SHA256 on API 26+, HMAC-SHA1 on
 * API 24-25 for platform compatibility) instead of the legacy fast SHA-256
 * verifier. Existing V1 PINs are migrated automatically after a successful
 * verification. Failed-attempt throttling is persisted so a process restart
 * does not reset the lockout state.
 */
class LockStore(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val random = SecureRandom()

    val configured: Boolean
        get() = (prefs.contains(KEY_DERIVED) && prefs.contains(KEY_SALT_V2)) ||
                (prefs.contains(KEY_LEGACY_HASH) && prefs.contains(KEY_LEGACY_SALT))

    var enabled: Boolean
        get() = prefs.getBoolean(KEY_ENABLED, false)
        set(value) = prefs.edit().putBoolean(KEY_ENABLED, value).apply()

    var biometricEnabled: Boolean
        get() = prefs.getBoolean(KEY_BIOMETRIC, true)
        set(value) = prefs.edit().putBoolean(KEY_BIOMETRIC, value).apply()

    /** Remaining lockout time in seconds, rounded up. */
    fun lockoutRemainingSeconds(): Long {
        val until = prefs.getLong(KEY_LOCKOUT_UNTIL, 0L)
        return ((until - System.currentTimeMillis() + 999L) / 1000L).coerceAtLeast(0L)
    }

    fun canAttempt(): Boolean = lockoutRemainingSeconds() == 0L

    fun setPin(pin: String) {
        require(pin.length in MIN_PIN_LENGTH..MAX_PIN_LENGTH && pin.all { it.isDigit() })
        val salt = ByteArray(SALT_BYTES).also(random::nextBytes)
        val derived = derive(pin, salt, PBKDF2_ITERATIONS)
        prefs.edit()
            .putInt(KEY_FORMAT_VERSION, FORMAT_V2)
            .putInt(KEY_ITERATIONS, PBKDF2_ITERATIONS)
            .putString(KEY_KDF, currentKdf())
            .putString(KEY_SALT_V2, Base64.encodeToString(salt, Base64.NO_WRAP))
            .putString(KEY_DERIVED, Base64.encodeToString(derived, Base64.NO_WRAP))
            .remove(KEY_LEGACY_SALT)
            .remove(KEY_LEGACY_HASH)
            .remove(KEY_LOCKOUT_UNTIL)
            .remove(KEY_FAILED_ATTEMPTS)
            .apply()
    }

    /**
     * Verifies the supplied PIN. A successful legacy verification is upgraded
     * in-place to V2 so the next login uses only PBKDF2.
     */
    fun verifyPin(pin: String): Boolean {
        if (!canAttempt()) return false
        if (pin.length !in MIN_PIN_LENGTH..MAX_PIN_LENGTH || !pin.all { it.isDigit() }) {
            registerFailure()
            return false
        }

        val ok = runCatching {
            if (hasV2()) {
                val salt = Base64.decode(prefs.getString(KEY_SALT_V2, ""), Base64.DEFAULT)
                val expected = Base64.decode(prefs.getString(KEY_DERIVED, ""), Base64.DEFAULT)
                val iterations = prefs.getInt(KEY_ITERATIONS, PBKDF2_ITERATIONS).coerceIn(50_000, 500_000)
                val kdf = prefs.getString(KEY_KDF, currentKdf()) ?: currentKdf()
                MessageDigest.isEqual(expected, derive(pin, salt, iterations, kdf))
            } else {
                val salt = Base64.decode(prefs.getString(KEY_LEGACY_SALT, ""), Base64.DEFAULT)
                val expected = Base64.decode(prefs.getString(KEY_LEGACY_HASH, ""), Base64.DEFAULT)
                val legacyOk = MessageDigest.isEqual(expected, legacyHash(pin, salt))
                if (legacyOk) {
                    // Upgrade only after proving possession of the old PIN.
                    setPin(pin)
                }
                legacyOk
            }
        }.getOrDefault(false)

        if (ok) {
            clearFailures()
        } else {
            registerFailure()
        }
        return ok
    }

    private fun hasV2(): Boolean = prefs.contains(KEY_DERIVED) && prefs.contains(KEY_SALT_V2)

    private fun registerFailure() {
        val failures = (prefs.getInt(KEY_FAILED_ATTEMPTS, 0) + 1).coerceAtMost(MAX_FAILURES)
        val delaySeconds = when {
            failures < 5 -> 0L
            failures < 10 -> 15L
            failures < 15 -> 30L
            failures < 20 -> 60L
            failures < 25 -> 120L
            else -> 300L
        }
        val editor = prefs.edit().putInt(KEY_FAILED_ATTEMPTS, failures)
        if (delaySeconds > 0L) {
            editor.putLong(KEY_LOCKOUT_UNTIL, System.currentTimeMillis() + delaySeconds * 1000L)
        } else {
            editor.remove(KEY_LOCKOUT_UNTIL)
        }
        editor.apply()
    }

    private fun clearFailures() {
        prefs.edit().remove(KEY_FAILED_ATTEMPTS).remove(KEY_LOCKOUT_UNTIL).apply()
    }

    private fun derive(pin: String, salt: ByteArray, iterations: Int, kdf: String = currentKdf()): ByteArray {
        val spec = PBEKeySpec(
            pin.toCharArray(),
            salt,
            iterations,
            DERIVED_BITS
        )
        return try {
            SecretKeyFactory.getInstance(kdf)
                .generateSecret(spec)
                .encoded
        } finally {
            spec.clearPassword()
        }
    }

    private fun currentKdf(): String = if (Build.VERSION.SDK_INT >= 26) "PBKDF2WithHmacSHA256" else "PBKDF2WithHmacSHA1"

    private fun legacyHash(pin: String, salt: ByteArray): ByteArray {
        val pinBytes = pin.toByteArray(StandardCharsets.UTF_8)
        val combined = ByteArray(salt.size + pinBytes.size)
        System.arraycopy(salt, 0, combined, 0, salt.size)
        System.arraycopy(pinBytes, 0, combined, salt.size, pinBytes.size)
        return MessageDigest.getInstance("SHA-256").digest(combined)
    }

    companion object {
        private const val PREFS_NAME = "firewall_lock"
        private const val KEY_ENABLED = "enabled"
        private const val KEY_BIOMETRIC = "biometric"
        private const val KEY_FORMAT_VERSION = "format_version"
        private const val KEY_SALT_V2 = "salt_v2"
        private const val KEY_DERIVED = "derived"
        private const val KEY_ITERATIONS = "iterations"
        private const val KEY_KDF = "kdf"
        private const val KEY_LEGACY_SALT = "salt"
        private const val KEY_LEGACY_HASH = "hash"
        private const val KEY_FAILED_ATTEMPTS = "failed_attempts"
        private const val KEY_LOCKOUT_UNTIL = "lockout_until"

        private const val FORMAT_V2 = 2
        private const val SALT_BYTES = 16
        private const val DERIVED_BITS = 256
        private const val PBKDF2_ITERATIONS = 120_000
        private const val MIN_PIN_LENGTH = 4
        private const val MAX_PIN_LENGTH = 8
        private const val MAX_FAILURES = 100
    }
}
