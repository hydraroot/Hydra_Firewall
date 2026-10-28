package com.hydra.firewall.vpn

import java.math.BigInteger
import java.net.InetAddress

/**
 * Static analysis over the existing rule stores looking for redundant or
 * contradictory entries accumulated over time (e.g. a leftover per-app port
 * block that a broader global rule already makes irrelevant, or the same IP
 * blocked twice in slightly different notations). Pure read-only analysis:
 * it never changes a rule itself, it only proposes a specific deletion, and
 * the caller (UI) is what actually applies it.
 */
object RuleConflictAnalyzer {

    enum class Kind { DUPLICATE_IP, REDUNDANT_IP_RANGE, DUPLICATE_PORT_RULE, SHADOWED_PORT_RULE }

    data class Finding(
        val kind: Kind,
        val description: String,
        val removablePortRule: AdvancedRuleStore.Rule? = null,
        val removableIp: String? = null
    )

    fun analyze(ipBlockStore: IpBlockStore, advancedRuleStore: AdvancedRuleStore): List<Finding> {
        val findings = mutableListOf<Finding>()
        findings += analyzeIpBlocks(ipBlockStore)
        findings += analyzePortRules(advancedRuleStore)
        return findings
    }

    private fun analyzeIpBlocks(store: IpBlockStore): List<Finding> {
        val entries = store.getBlocked()
        val findings = mutableListOf<Finding>()
        for (i in entries.indices) {
            for (j in entries.indices) {
                if (i == j) continue
                val a = entries[i]
                val b = entries[j]
                if (a == b) continue
                if (rangeContains(a, b)) {
                    findings += Finding(
                        kind = Kind.REDUNDANT_IP_RANGE,
                        description = "\"$b\" ya está cubierto por \"$a\"",
                        removableIp = b
                    )
                }
            }
        }
        return findings.distinctBy { it.removableIp }
    }

    /** True if every address matched by [narrower] is also matched by [broader]. Best-effort:
     *  only handles exact/CIDR/range notations already accepted by IpBlockStore. */
    private fun rangeContains(broader: String, narrower: String): Boolean = runCatching {
        val (broaderLo, broaderHi, broaderFamily) = bounds(broader) ?: return false
        val (narrowLo, narrowHi, narrowFamily) = bounds(narrower) ?: return false
        if (broaderFamily != narrowFamily) return false
        broaderLo <= narrowLo && narrowHi <= broaderHi
    }.getOrDefault(false)

    private fun bounds(rule: String): Triple<BigInteger, BigInteger, Int>? {
        val r = rule.trim()
        return when {
            r.contains('/') -> {
                val parts = r.split('/', limit = 2)
                val addr = InetAddress.getByName(parts[0])
                val prefix = parts[1].toIntOrNull() ?: return null
                val size = addr.address.size * 8
                val base = BigInteger(1, addr.address)
                val hostBits = size - prefix
                val mask = if (hostBits == 0) BigInteger.ZERO else BigInteger.ONE.shiftLeft(hostBits).subtract(BigInteger.ONE)
                val lo = base.andNot(mask)
                val hi = lo.or(mask)
                Triple(lo, hi, addr.address.size)
            }
            r.contains('-') -> {
                val parts = r.split('-', limit = 2)
                val a = InetAddress.getByName(parts[0])
                val b = InetAddress.getByName(parts[1])
                Triple(BigInteger(1, a.address), BigInteger(1, b.address), a.address.size)
            }
            else -> {
                val a = InetAddress.getByName(r)
                val v = BigInteger(1, a.address)
                Triple(v, v, a.address.size)
            }
        }
    }

    private fun analyzePortRules(store: AdvancedRuleStore): List<Finding> {
        val rules = store.getAll()
        val findings = mutableListOf<Finding>()

        // Exact duplicates (same scope/protocol/range, different action) - the store itself
        // dedupes identical entries on save, so a "duplicate" here means overlapping ranges
        // for the same uid+protocol that disagree, which is the practically useful case.
        for (rule in rules) {
            val sameScopeOthers = rules.filter {
                it != rule && it.uid == rule.uid && it.protocol == rule.protocol &&
                    it.startPort <= rule.startPort && it.endPort >= rule.endPort &&
                    !(it.startPort == rule.startPort && it.endPort == rule.endPort)
            }
            val broader = sameScopeOthers.minByOrNull { it.endPort - it.startPort }
            if (broader != null) {
                if (broader.allowed != rule.allowed) {
                    findings += Finding(
                        kind = Kind.SHADOWED_PORT_RULE,
                        description = "Regla ${rule.protocol} ${rule.startPort}-${rule.endPort} (uid ${rule.uid}) contradice a la regla más amplia ${broader.startPort}-${broader.endPort}; esta última gana igual porque el motor prioriza el rango más angosto, revisá si la angosta sigue haciendo falta",
                        removablePortRule = null
                    )
                } else {
                    findings += Finding(
                        kind = Kind.DUPLICATE_PORT_RULE,
                        description = "Regla ${rule.protocol} ${rule.startPort}-${rule.endPort} (uid ${rule.uid}) es redundante: ${broader.startPort}-${broader.endPort} ya hace lo mismo",
                        removablePortRule = rule
                    )
                }
            }
        }
        // Global rule fully duplicated by an identical global rule is prevented by the store;
        // per-uid rule that exactly matches the global rule's action is a softer redundancy hint.
        val globalRules = rules.filter { it.uid == AdvancedRuleStore.GLOBAL_UID }
        for (rule in rules.filter { it.uid != AdvancedRuleStore.GLOBAL_UID }) {
            val matchingGlobal = globalRules.firstOrNull {
                it.protocol == rule.protocol && it.startPort == rule.startPort && it.endPort == rule.endPort && it.allowed == rule.allowed
            }
            if (matchingGlobal != null) {
                findings += Finding(
                    kind = Kind.DUPLICATE_PORT_RULE,
                    description = "Regla ${rule.protocol} ${rule.startPort}-${rule.endPort} (uid ${rule.uid}) coincide exactamente con una regla global ya existente",
                    removablePortRule = rule
                )
            }
        }
        return findings.distinctBy { it.description }
    }
}
