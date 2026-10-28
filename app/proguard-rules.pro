# Hydra release hardening
# Android framework entry points. R8 keeps referenced application code automatically.
-keep class com.hydra.firewall.vpn.FirewallVpnService { *; }
-keep class com.hydra.firewall.vpn.BootReceiver { *; }
-keep class com.hydra.firewall.AppAccessRequestActivity { *; }
-keep class com.hydra.firewall.LockScreen { *; }
-keepclassmembers enum * { *; }
-dontwarn kotlinx.coroutines.**
