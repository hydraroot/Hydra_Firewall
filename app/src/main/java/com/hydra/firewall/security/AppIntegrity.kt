package com.hydra.firewall.security

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import java.security.MessageDigest

/** Local, offline integrity signals. It deliberately does not claim to detect every form of repackaging. */
object AppIntegrity {
    data class Result(val releaseLike: Boolean, val signerPresent: Boolean, val signerSha256: String?, val detail: String)

    fun inspect(context: Context): Result {
        val app = context.applicationInfo
        val debug = (app.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE) != 0
        val signatures = runCatching {
            val pm = context.packageManager
            if (Build.VERSION.SDK_INT >= 28) {
                val info = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                info.signingInfo?.apkContentsSigners?.toList() ?: emptyList()
            } else {
                @Suppress("DEPRECATION")
                val info = pm.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
                @Suppress("DEPRECATION")
                info.signatures?.toList() ?: emptyList()
            }
        }.getOrDefault(emptyList())
        val digest = signatures.firstOrNull()?.let { cert ->
            MessageDigest.getInstance("SHA-256").digest(cert.toByteArray()).joinToString("") { "%02X".format(it) }
        }
        val ok = !debug && signatures.isNotEmpty()
        val detail = when { debug -> "debuggable_build"; signatures.isEmpty() -> "signer_unavailable"; else -> "release_signature_present" }
        return Result(ok, signatures.isNotEmpty(), digest, detail)
    }
}
