package com.hydra.firewall.security

import android.util.Base64
import org.json.JSONObject
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.nio.charset.StandardCharsets

object ThreatSignatureVerifier {
    private const val ALGORITHM = "SHA256withECDSA"
    // P-256 public key. Private key is NOT shipped in Hydra.
    private const val DEFAULT_PUBLIC_KEY_B64 = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENTRk3PVkMi+VV6Wx3K/Q1bskCvterMtBMY8kPTAuN1ME6p2HIdn/hv4fii7xFOpL9Ha5pqenDnT4u8UDWRb0Bg=="

    /** Clave de build (HYDRA_THREAT_PUBLIC_KEY) si existe; si no, la clave original del proyecto. */
    private val PUBLIC_KEY_B64: String
        get() = com.hydra.firewall.BuildConfig.THREAT_PUBLIC_KEY.trim().ifEmpty { DEFAULT_PUBLIC_KEY_B64 }

    fun verifyAndExtract(envelopeText: String): String? = runCatching {
        val root = JSONObject(envelopeText)
        require(root.optInt("schema", 0) == 1)
        val payloadB64 = root.getString("payload_base64")
        val signatureB64 = root.getString("signature_base64")
        val algorithm = root.optString("algorithm", ALGORITHM)
        require(algorithm == ALGORITHM)
        val payload = Base64.decode(payloadB64, Base64.DEFAULT)
        val signature = Base64.decode(signatureB64, Base64.DEFAULT)
        val verifier = Signature.getInstance(ALGORITHM)
        verifier.initVerify(publicKey())
        verifier.update(payload)
        require(verifier.verify(signature))
        String(payload, StandardCharsets.UTF_8)
    }.getOrNull()

    private fun publicKey(): PublicKey {
        val encoded = Base64.decode(PUBLIC_KEY_B64, Base64.DEFAULT)
        return KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(encoded))
    }
}
