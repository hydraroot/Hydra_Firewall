// Hydra seed rules (subset YARA-Lite). Son SEÑALES DE REVISIÓN por combinación de capacidades,
// no pruebas de malware: apps legítimas (bancos, gestores de archivos, MDM) pueden coincidir.

rule Hydra_Android_Suspicious_Sms_Overlay_Admin {
    meta:
        family = "android_suspicious_capabilities"
        severity = 55
        description = "Combination of SMS, overlay and device-admin markers; requires review, not proof of malware."
    strings:
        $sms = "android.permission.READ_SMS" ascii nocase
        $overlay = "android.permission.SYSTEM_ALERT_WINDOW" ascii nocase
        $admin = "android.permission.BIND_DEVICE_ADMIN" ascii nocase
    condition:
        2 of them
}

// Antes: 2 de 4 incluyendo "classes.dex", demasiado laxo (casi cualquier app con SDK de anuncios).
rule Hydra_Android_Dynamic_Payload_Loader {
    meta:
        family = "android_suspicious_loader"
        severity = 60
        description = "Dynamic DEX loading + package-archive inspection + install-packages permission (dropper pattern)."
    strings:
        $dex = "DexClassLoader" ascii nocase
        $archive = "getPackageArchiveInfo" ascii nocase
        $install = "android.permission.REQUEST_INSTALL_PACKAGES" ascii nocase
    condition:
        all of them
}

rule Hydra_Android_Banking_Trojan_Capabilities {
    meta:
        family = "android_banking_trojan_pattern"
        severity = 65
        description = "Accessibility service + screen overlay + SMS access + install-packages: common banking-trojan combination."
    strings:
        $acc = "android.permission.BIND_ACCESSIBILITY_SERVICE" ascii nocase
        $overlay = "android.permission.SYSTEM_ALERT_WINDOW" ascii nocase
        $sms = "android.permission.READ_SMS" ascii nocase
        $install = "android.permission.REQUEST_INSTALL_PACKAGES" ascii nocase
    condition:
        all of them
}

rule Hydra_Android_Sms_Interceptor {
    meta:
        family = "android_sms_stealer_pattern"
        severity = 60
        description = "Receives and reads SMS, can send SMS, and aborts the broadcast so the user does not see it."
    strings:
        $recv = "android.permission.RECEIVE_SMS" ascii nocase
        $read = "android.permission.READ_SMS" ascii nocase
        $send = "android.permission.SEND_SMS" ascii nocase
        $abort = "abortBroadcast" ascii
    condition:
        all of them
}

rule Hydra_Android_Ransom_Lock_Pattern {
    meta:
        family = "android_locker_pattern"
        severity = 65
        description = "Device-admin lock/wipe APIs with overlay permission (screen-locker / ransomware pattern)."
    strings:
        $admin = "android.permission.BIND_DEVICE_ADMIN" ascii nocase
        $lock = "lockNow" ascii
        $reset = "resetPassword" ascii
        $overlay = "android.permission.SYSTEM_ALERT_WINDOW" ascii nocase
    condition:
        all of them
}

rule Hydra_Android_Stalkerware_Pattern {
    meta:
        family = "android_stalkerware_pattern"
        severity = 50
        description = "Audio recording, call log, SMS and background location together: spyware/stalkerware pattern; review."
    strings:
        $mic = "android.permission.RECORD_AUDIO" ascii nocase
        $calls = "android.permission.READ_CALL_LOG" ascii nocase
        $sms = "android.permission.READ_SMS" ascii nocase
        $loc = "android.permission.ACCESS_BACKGROUND_LOCATION" ascii nocase
    condition:
        all of them
}
