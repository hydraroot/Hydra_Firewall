package com.hydra.firewall

import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import kotlinx.coroutines.delay
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.hydra.firewall.vpn.LockStore

@Composable
fun LockScreen(lockStore: LockStore, onUnlocked: () -> Unit) {
    val context = androidx.compose.ui.platform.LocalContext.current
    val activity = context as? FragmentActivity
    var pin by remember { mutableStateOf("") }
    var error by remember { mutableStateOf(false) }
    var biometricAttempted by remember { mutableStateOf(false) }
    var nowMs by remember { mutableStateOf(System.currentTimeMillis()) }
    var verifying by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    LaunchedEffect(lockStore) {
        while (true) {
            nowMs = System.currentTimeMillis()
            delay(1000L)
        }
    }

    var biometricAvailable by remember { mutableStateOf(false) }
    var biometricError by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(activity, lockStore.biometricEnabled, biometricAttempted) {
        if (activity == null || !lockStore.biometricEnabled || biometricAttempted) return@LaunchedEffect
        delay(250L)
        val availability = runCatching {
            BiometricManager.from(activity).canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK)
        }.getOrDefault(BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE)
        biometricAvailable = availability == BiometricManager.BIOMETRIC_SUCCESS
        if (!biometricAvailable) {
            biometricAttempted = true
            return@LaunchedEffect
        }

        val executor = ContextCompat.getMainExecutor(activity)
        val prompt = BiometricPrompt(activity, executor, object : BiometricPrompt.AuthenticationCallback() {
            override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                biometricAttempted = true
                biometricError = null
                onUnlocked()
            }
            override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                biometricAttempted = true
                biometricError = errString.toString()
            }
            override fun onAuthenticationFailed() {
                biometricError = if (AppSettings(context).language.isEnglish()) "Fingerprint not recognized." else "Huella no reconocida."
            }
        })
        prompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("Hydra Firewall")
                .setSubtitle(tr(context, "lock_app"))
                .setDescription(if (AppSettings(context).language.isEnglish()) "Authenticate with your fingerprint to unlock Hydra Firewall." else "Autenticá con tu huella para desbloquear Hydra Firewall.")
                .setNegativeButtonText(if (AppSettings(context).language.isEnglish()) "Use PIN" else "Usar PIN")
                .build()
        )
    }


    val remaining = if (nowMs >= 0L) lockStore.lockoutRemainingSeconds().coerceAtLeast(0L) else 0L

    Column(
        modifier = Modifier.padding(24.dp).fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        Text("Hydra Firewall", style = MaterialTheme.typography.headlineSmall)
        Text(if (AppSettings(context).language.isEnglish()) "Authentication required" else "Se requiere autenticación")
        OutlinedTextField(
            value = pin,
            onValueChange = { if (it.length <= 8 && it.all(Char::isDigit)) { pin = it; error = false } },
            singleLine = true,
            label = { Text("PIN") },
            visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
            modifier = Modifier.fillMaxWidth()
        )
        if (remaining > 0L) {
            Text(
                if (AppSettings(context).language.isEnglish()) "Too many attempts. Try again in ${remaining}s." else "Demasiados intentos. Reintentá en ${remaining}s.",
                color = MaterialTheme.colorScheme.error
            )
        } else if (error) {
            Text(if (AppSettings(context).language.isEnglish()) "Invalid PIN" else "PIN incorrecto", color = MaterialTheme.colorScheme.error)
        }
        if (biometricAvailable && biometricAttempted) {
            androidx.compose.material3.TextButton(onClick = { biometricAttempted = false; biometricError = null }) {
                Text(if (AppSettings(context).language.isEnglish()) "Use fingerprint" else "Usar huella")
            }
        }
        biometricError?.let { msg ->
            Text(msg, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
        }
        Button(
            onClick = {
                if (verifying) return@Button
                val submittedPin = pin
                verifying = true
                error = false
                scope.launch(Dispatchers.Default) {
                    val ok = lockStore.verifyPin(submittedPin)
                    kotlinx.coroutines.withContext(Dispatchers.Main) {
                        verifying = false
                        if (ok) {
                            onUnlocked()
                        } else {
                            error = true
                            pin = ""
                        }
                    }
                }
            },
            enabled = remaining == 0L && pin.length in 4..8 && !verifying,
            modifier = Modifier.fillMaxWidth()
        ) {
            Text(
                when {
                    verifying -> if (AppSettings(context).language.isEnglish()) "Verifying..." else "Verificando..."
                    AppSettings(context).language.isEnglish() -> "Unlock"
                    else -> "Desbloquear"
                }
            )
        }
    }
}
