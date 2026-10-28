package com.hydra.firewall.vpn

enum class NetworkKind {
    WIFI,
    MOBILE,
    OTHER,
    NONE;

    val displayName: String
        get() = when (this) {
            WIFI -> "Wi‑Fi"
            MOBILE -> "Datos móviles"
            OTHER -> "Otra red"
            NONE -> "Sin red"
        }
}
