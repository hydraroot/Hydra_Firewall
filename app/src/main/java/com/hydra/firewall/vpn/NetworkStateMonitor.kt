package com.hydra.firewall.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicReference

data class NetworkState(val kind: NetworkKind, val roaming: Boolean)

class NetworkStateMonitor(
    context: Context,
    private val onChanged: (NetworkState) -> Unit
) {
    companion object { private const val TAG = "NetworkStateMonitor" }

    private val connectivityManager = context.applicationContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private val stateRef = AtomicReference(NetworkState(NetworkKind.NONE, false))
    private val physicalNetworks = ConcurrentHashMap<Network, NetworkCapabilities>()
    @Volatile private var selectedPhysicalNetwork: Network? = null
    private var started = false

    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            refreshNetwork(network)
        }

        override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
            if (isEligiblePhysical(caps)) {
                physicalNetworks[network] = caps
            } else {
                physicalNetworks.remove(network)
            }
            publishBest()
        }

        override fun onLost(network: Network) {
            physicalNetworks.remove(network)
            if (selectedPhysicalNetwork == network) selectedPhysicalNetwork = null
            publishBest()
        }
    }

    val current: NetworkState get() = stateRef.get()
    fun currentUnderlyingNetwork(): Network? = selectedPhysicalNetwork

    fun start() {
        if (started) return
        try {
            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build()
            connectivityManager.registerNetworkCallback(request, callback)
            started = true

            // Prime the physical set immediately. Do not use activeNetwork here:
            // once HYDRA is established, activeNetwork may itself be the VPN.
            connectivityManager.allNetworks.forEach(::refreshNetwork)
            publishBest()
        } catch (e: Exception) {
            Log.e(TAG, "No se pudo registrar NetworkCallback físico", e)
            throw e
        }
    }

    fun stop() {
        if (!started) return
        runCatching { connectivityManager.unregisterNetworkCallback(callback) }
        started = false
        physicalNetworks.clear()
        selectedPhysicalNetwork = null
        stateRef.set(NetworkState(NetworkKind.NONE, false))
    }

    private fun refreshNetwork(network: Network) {
        val caps = runCatching { connectivityManager.getNetworkCapabilities(network) }.getOrNull()
        if (caps != null && isEligiblePhysical(caps)) {
            physicalNetworks[network] = caps
        } else {
            physicalNetworks.remove(network)
        }
        publishBest()
    }

    private fun isEligiblePhysical(caps: NetworkCapabilities): Boolean {
        if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) return false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP &&
            !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) return false
        return caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ||
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
    }

    private fun publishBest() {
        val best = physicalNetworks.entries
            .sortedWith(compareByDescending<Map.Entry<Network, NetworkCapabilities>> { rank(it.value) }
                .thenByDescending { if (Build.VERSION.SDK_INT >= 23 && it.value.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) 1 else 0 })
            .firstOrNull()

        selectedPhysicalNetwork = best?.key
        val caps = best?.value
        val next = if (caps == null) {
            NetworkState(NetworkKind.NONE, false)
        } else {
            val kind = when {
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> NetworkKind.WIFI
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> NetworkKind.MOBILE
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> NetworkKind.OTHER
                else -> NetworkKind.OTHER
            }
            val roaming = kind == NetworkKind.MOBILE &&
                !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING)
            NetworkState(kind, roaming)
        }
        val prev = stateRef.getAndSet(next)
        if (prev != next) onChanged(next)
    }

    private fun rank(caps: NetworkCapabilities): Int = when {
        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> 300
        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 250
        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> 200
        else -> 0
    }
}
