package com.hydra.firewall

import android.content.Context
import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import com.hydra.firewall.vpn.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@Composable
internal fun SecuritySettingsSection(context: Context, lockStore: LockStore, onChanged: () -> Unit) {
    var enabled by remember { mutableStateOf(lockStore.enabled && lockStore.configured) }
    var biometric by remember { mutableStateOf(lockStore.biometricEnabled) }
    var showPinDialog by remember { mutableStateOf(false) }
    var showChangePinDialog by remember { mutableStateOf(false) }
    var currentPin by remember { mutableStateOf("") }
    var pin by remember { mutableStateOf("") }
    var pin2 by remember { mutableStateOf("") }
    var pinError by remember { mutableStateOf(false) }
    var cryptoBusy by remember { mutableStateOf(false) }
    var showDisableDialog by remember { mutableStateOf(false) }
    var disablePin by remember { mutableStateOf("") }
    var disableError by remember { mutableStateOf(false) }
    val scope = rememberCoroutineScope()

    SettingSwitchRow(tr(context, "lock_app"), tr(context, "lock_sub"), enabled) { checked ->
        if (checked) {
            if (lockStore.configured) {
                lockStore.enabled = true
                enabled = true
            } else {
                pin = ""; pin2 = ""; pinError = false; showPinDialog = true
            }
        } else if (lockStore.configured) {
            // Desactivar el bloqueo exige el PIN actual (la pantalla puede haber quedado abierta).
            disablePin = ""; disableError = false; showDisableDialog = true
        } else {
            lockStore.enabled = false
            enabled = false
            onChanged()
        }
    }

    if (showDisableDialog) {
        AlertDialog(
            containerColor = hydraDialogColors().first,
            titleContentColor = hydraDialogColors().second,
            textContentColor = hydraDialogColors().third,
            onDismissRequest = { showDisableDialog = false },
            title = { Text(if (AppSettings(context).language.isEnglish()) "Turn off lock" else "Desactivar bloqueo") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(disablePin, { if (it.length <= 8 && it.all(Char::isDigit)) { disablePin = it; disableError = false } }, singleLine = true,
                        label = { Text(if (AppSettings(context).language.isEnglish()) "Current PIN" else "PIN actual") }, visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword))
                    if (disableError) Text(if (AppSettings(context).language.isEnglish()) "Invalid PIN or temporarily locked." else "PIN incorrecto o bloqueado temporalmente.", color = MaterialTheme.colorScheme.error)
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    if (cryptoBusy) return@TextButton
                    val typed = disablePin
                    cryptoBusy = true
                    scope.launch(Dispatchers.Default) {
                        val ok = lockStore.verifyPin(typed)
                        withContext(Dispatchers.Main) {
                            cryptoBusy = false
                            if (ok) {
                                lockStore.enabled = false
                                lockStore.biometricEnabled = false
                                enabled = false
                                biometric = false
                                showDisableDialog = false
                                onChanged()
                            } else disableError = true
                        }
                    }
                }, enabled = !cryptoBusy && disablePin.length in 4..8) { Text(tr(context, "save")) }
            },
            dismissButton = { TextButton(onClick = { showDisableDialog = false }) { Text(tr(context, "cancel")) } }
        )
    }

    val biometricAllowed = enabled && lockStore.configured
    val biometricSubtitle = if (biometricAllowed) tr(context, "fingerprint_sub") else
        if (AppSettings(context).language.isEnglish()) "Enable PIN protection first; fingerprint unlock is optional and off by default." else
            "Primero activá la protección con PIN; la huella es opcional y viene desactivada."
    SettingSwitchRow(tr(context, "use_fingerprint"), biometricSubtitle, biometric, enabled = biometricAllowed) { checked ->
        biometric = checked
        lockStore.biometricEnabled = checked
    }

    if (enabled && lockStore.configured) {
        TextButton(onClick = { currentPin = ""; pin = ""; pin2 = ""; pinError = false; showChangePinDialog = true }) {
            Text(tr(context, "change_pin"))
        }
    }

    if (showPinDialog) {
        AlertDialog(
            containerColor = hydraDialogColors().first,
            titleContentColor = hydraDialogColors().second,
            textContentColor = hydraDialogColors().third,
            onDismissRequest = { showPinDialog = false },
            title = { Text(if (AppSettings(context).language.isEnglish()) "Create PIN" else "Crear PIN") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(pin, { if (it.length <= 8 && it.all(Char::isDigit)) { pin = it; pinError = false } }, singleLine = true,
                        label = { Text(if (AppSettings(context).language.isEnglish()) "PIN (5-8 digits)" else "PIN (5-8 dígitos)") }, visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword))
                    OutlinedTextField(pin2, { if (it.length <= 8 && it.all(Char::isDigit)) { pin2 = it; pinError = false } }, singleLine = true,
                        label = { Text(if (AppSettings(context).language.isEnglish()) "Repeat PIN" else "Repetir PIN") }, visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword))
                    if (pinError) Text(if (AppSettings(context).language.isEnglish()) "PINs do not match or are invalid (minimum 5 digits)." else "Los PIN no coinciden o no son válidos (mínimo 5 dígitos).", color = MaterialTheme.colorScheme.error)
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    if (cryptoBusy) return@TextButton
                    if (pin.length in 5..8 && pin == pin2) {
                        val newPin = pin
                        cryptoBusy = true
                        scope.launch(Dispatchers.Default) {
                            lockStore.setPin(newPin)
                            withContext(Dispatchers.Main) {
                                cryptoBusy = false
                                lockStore.enabled = true
                                enabled = true
                                showPinDialog = false
                            }
                        }
                    } else pinError = true
                }, enabled = !cryptoBusy) { Text(if (cryptoBusy) (if (AppSettings(context).language.isEnglish()) "Saving..." else "Guardando...") else tr(context, "save")) }
            },
            dismissButton = { TextButton(onClick = { showPinDialog = false }) { Text(tr(context, "cancel")) } }
        )
    }

    if (showChangePinDialog) {
        AlertDialog(
            containerColor = hydraDialogColors().first,
            titleContentColor = hydraDialogColors().second,
            textContentColor = hydraDialogColors().third,
            onDismissRequest = { showChangePinDialog = false },
            title = { Text(tr(context, "change_pin")) },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    OutlinedTextField(currentPin, { if (it.length <= 8 && it.all(Char::isDigit)) { currentPin = it; pinError = false } }, singleLine = true,
                        label = { Text(if (AppSettings(context).language.isEnglish()) "Current PIN" else "PIN actual") }, visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword))
                    OutlinedTextField(pin, { if (it.length <= 8 && it.all(Char::isDigit)) { pin = it; pinError = false } }, singleLine = true,
                        label = { Text(if (AppSettings(context).language.isEnglish()) "PIN (5-8 digits)" else "PIN (5-8 dígitos)") }, visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword))
                    OutlinedTextField(pin2, { if (it.length <= 8 && it.all(Char::isDigit)) { pin2 = it; pinError = false } }, singleLine = true,
                        label = { Text(if (AppSettings(context).language.isEnglish()) "Repeat PIN" else "Repetir PIN") }, visualTransformation = PasswordVisualTransformation(),
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword))
                    if (pinError) Text(if (AppSettings(context).language.isEnglish()) "Current PIN invalid, new PINs do not match, or PIN is temporarily locked." else "PIN actual incorrecto, los nuevos PIN no coinciden o el PIN está temporalmente bloqueado.", color = MaterialTheme.colorScheme.error)
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    if (cryptoBusy) return@TextButton
                    if (currentPin.length in 4..8 && pin.length in 5..8 && pin2.length in 5..8) {
                        val oldPin = currentPin
                        val newPin = pin
                        if (newPin != pin2) {
                            pinError = true
                            return@TextButton
                        }
                        cryptoBusy = true
                        scope.launch(Dispatchers.Default) {
                            val verified = lockStore.verifyPin(oldPin)
                            if (verified) lockStore.setPin(newPin)
                            withContext(Dispatchers.Main) {
                                cryptoBusy = false
                                if (verified) showChangePinDialog = false else pinError = true
                            }
                        }
                    } else pinError = true
                }, enabled = !cryptoBusy && currentPin.length in 4..8 && pin.length in 5..8 && pin2.length in 5..8) { Text(if (cryptoBusy) (if (AppSettings(context).language.isEnglish()) "Saving..." else "Guardando...") else tr(context, "save")) }
            },
            dismissButton = { TextButton(onClick = { showChangePinDialog = false }) { Text(tr(context, "cancel")) } }
        )
    }
}

@Composable
internal fun ScheduleEditor(context: Context, initial: RuleStore.Schedule, onChanged: (RuleStore.Schedule) -> Unit) {
    var schedule by remember(initial) { mutableStateOf(initial) }
    val english = AppSettings(context).language.isEnglish()
    val dayLabels = if (english) listOf("M", "T", "W", "T", "F", "S", "S") else listOf("L", "M", "X", "J", "V", "S", "D")
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        SettingSwitchRow(tr(context, "blocked_by_schedule"), tr(context, "schedule_sub"), schedule.enabled) {
            schedule = schedule.copy(enabled = it)
            onChanged(schedule)
        }
        if (schedule.enabled) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
                TimeStepper(context, tr(context, "from"), schedule.startMinutes) { v -> schedule = schedule.copy(startMinutes = v); onChanged(schedule) }
                TimeStepper(context, tr(context, "to"), schedule.endMinutes) { v -> schedule = schedule.copy(endMinutes = v); onChanged(schedule) }
            }
            Text(tr(context, "days"), style = MaterialTheme.typography.labelSmall)
            HydraHorizontalRow(Modifier.fillMaxWidth().height(36.dp), horizontalArrangement = Arrangement.spacedBy(4.dp)) {
                dayLabels.forEachIndexed { i, label ->
                    val selected = (schedule.daysMask and (1 shl i)) != 0
                    HydraChoiceButton(selected, label, MaterialTheme.colorScheme.primary, MaterialTheme.colorScheme.onPrimary, onClick = {
                        val mask = if (selected) schedule.daysMask and (1 shl i).inv() else schedule.daysMask or (1 shl i)
                        schedule = schedule.copy(daysMask = mask)
                        onChanged(schedule)
                    }, modifier=Modifier.height(30.dp), fontSize=11.sp)
                }
            }
            Text(tr(context, "schedule_all_day"), style = MaterialTheme.typography.labelSmall)
        }
    }
}

@Composable
internal fun TimeStepper(context: Context, label: String, minutes: Int, onChange: (Int) -> Unit) {
    Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.width(142.dp)) {
        Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.fillMaxWidth()) {
            Text(label, style = MaterialTheme.typography.labelSmall)
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.Center) {
                TextButton(
                    onClick = { onChange((minutes - 30 + 1440) % 1440) },
                    contentPadding = PaddingValues(0.dp),
                    modifier = Modifier.size(30.dp)
                ) { Text("−", fontSize = 18.sp) }
                Text("%02d:%02d".format(minutes / 60, minutes % 60), style = MaterialTheme.typography.bodyMedium, modifier = Modifier.width(50.dp), textAlign = TextAlign.Center)
                TextButton(
                    onClick = { onChange((minutes + 30) % 1440) },
                    contentPadding = PaddingValues(0.dp),
                    modifier = Modifier.size(30.dp)
                ) { Text("+", fontSize = 18.sp) }
            }
        }
    }
}
