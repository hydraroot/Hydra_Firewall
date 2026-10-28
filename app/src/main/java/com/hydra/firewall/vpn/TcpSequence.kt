package com.hydra.firewall.vpn

/**
 * Unsigned 32-bit TCP sequence helpers (RFC 1982 serial number arithmetic).
 *
 * At exactly half the 32-bit space (distance == 2^31) the ordering is
 * mathematically undefined by the RFC. This implementation resolves that
 * single boundary case deterministically by comparing the raw unsigned
 * values, which guarantees compare(a, b) == -compare(b, a) for every input,
 * including that boundary.
 */
object TcpSequence {
    private const val MASK = 0xFFFF_FFFFL
    private const val HALF = 0x8000_0000L

    fun add(seq: Long, delta: Long): Long = (seq + delta) and MASK

    /** -1 if a is before b, 0 if equal, +1 if a is after b. */
    fun compare(a: Long, b: Long): Int {
        val aa = a and MASK
        val bb = b and MASK
        if (aa == bb) return 0
        val diff = (aa - bb) and MASK
        return when {
            diff < HALF -> 1
            diff > HALF -> -1
            else -> if (aa < bb) -1 else 1 // diff == HALF: undefined by RFC 1982, resolved deterministically
        }
    }

    fun before(a: Long, b: Long): Boolean = compare(a, b) < 0
    fun after(a: Long, b: Long): Boolean = compare(a, b) > 0

    /** Forward distance from a to b in the 32-bit sequence space. */
    fun distance(a: Long, b: Long): Long = ((b and MASK) - (a and MASK)) and MASK
}
