package com.hydra.firewall.vpn

import java.net.InetAddress

/** "host:port" for IPv4 and "[host]:port" for IPv6; shared by the engines, prompts and diagnostics. */
internal fun formatEndpoint(addr: InetAddress, port: Int): String {
    val host = addr.hostAddress ?: "?"
    return if (host.contains(':')) "[$host]:$port" else "$host:$port"
}
