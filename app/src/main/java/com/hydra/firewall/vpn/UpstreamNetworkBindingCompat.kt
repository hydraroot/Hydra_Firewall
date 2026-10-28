package com.hydra.firewall.vpn

import android.net.VpnService
import java.net.DatagramSocket
import java.net.Socket

/**
 * FIX148 compile/runtime compatibility helper.
 *
 * The forwarding engines intentionally depend on VpnService as their public
 * constructor type, while the physical-network binding helper lives on the
 * concrete FirewallVpnService. Keep the engine API generic and bridge to the
 * concrete service here.
 */
internal fun VpnService.bindUpstreamSocketToPhysicalNetworkCompat(socket: Socket): Boolean {
    val firewallService = this as? FirewallVpnService
    if (firewallService == null) {
        // Unit/instrumentation tests may provide a plain VpnService. In that
        // case preserve the previous protect-only fallback instead of failing
        // the flow solely because physical-network binding is unavailable.
        DiagnosticLogger.logServiceEvent(
            "UPSTREAM_NETWORK_BIND_SKIPPED reason=SERVICE_NOT_FIREWALL_VPN_SERVICE"
        )
        return true
    }
    return firewallService.bindUpstreamSocketToPhysicalNetwork(socket)
}

internal fun VpnService.bindUpstreamSocketToPhysicalNetworkCompat(socket: DatagramSocket): Boolean {
    val firewallService = this as? FirewallVpnService
    if (firewallService == null) {
        DiagnosticLogger.logServiceEvent(
            "UPSTREAM_NETWORK_BIND_SKIPPED reason=SERVICE_NOT_FIREWALL_VPN_SERVICE datagram=true"
        )
        return true
    }
    return firewallService.bindUpstreamSocketToPhysicalNetwork(socket)
}
