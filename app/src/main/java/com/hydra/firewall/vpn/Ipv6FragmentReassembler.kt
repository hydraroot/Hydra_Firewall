package com.hydra.firewall.vpn

import java.util.LinkedHashMap

/**
 * Bounded IPv6 Fragment header reassembly for packets whose upper-layer protocol
 * is TCP, UDP, or ICMPv6.
 *
 * Limits are intentionally conservative to prevent a malicious peer from using
 * the VPN as an unbounded fragment cache.
 */
class Ipv6FragmentReassembler {
    private data class Key(
        val source: ByteArray,
        val destination: ByteArray,
        val identification: Long
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Key) return false
            return identification == other.identification &&
                source.contentEquals(other.source) &&
                destination.contentEquals(other.destination)
        }

        override fun hashCode(): Int {
            var result = source.contentHashCode()
            result = 31 * result + destination.contentHashCode()
            result = 31 * result + identification.hashCode()
            return result
        }
    }

    private data class Fragment(
        val offset: Int,
        val payload: ByteArray,
        val more: Boolean
    )

    private data class Entry(
        val key: Key,
        val prefix: ByteArray,
        val fragmentHeaderOffset: Int,
        val nextHeader: Int,
        val createdAtMs: Long,
        val fragments: MutableList<Fragment> = mutableListOf(),
        var totalPayloadLength: Int? = null
    )

    companion object {
        private const val FRAGMENT_HEADER_LENGTH = 8
        private const val MAX_ENTRIES = 64
        private const val MAX_FRAGMENTS_PER_ENTRY = 32
        private const val MAX_REASSEMBLED_PACKET = 65575
        private const val TIMEOUT_MS = 5_000L
        private const val MAX_FRAGMENT_PAYLOAD = 65535
        private const val NEXT_FRAGMENT = IPv6Header.NEXT_FRAGMENT
    }

    private val entries = object : LinkedHashMap<Key, Entry>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Key, Entry>?): Boolean {
            return size > MAX_ENTRIES
        }
    }

    @Synchronized
    fun accept(packet: ByteArray): ByteArray? {
        val now = System.currentTimeMillis()
        purgeExpired(now)
        if (packet.size < IPv6Header.BASE_HEADER_LENGTH) return null
        if (((packet[0].toInt() and 0xFF) ushr 4) != 6) return null

        val payloadLength = u16(packet, 4)
        val total = 40 + payloadLength
        if (total > packet.size || total < 40) return null

        var next = packet[6].toInt() and 0xFF
        var offset = 40
        var extCount = 0
        var extBytes = 0

        // Walk only until the Fragment header. Other extension headers are retained
        // in the prefix so the reconstructed packet can be parsed normally later.
        while (next != NEXT_FRAGMENT) {
            if (next != IPv6Header.NEXT_HOP_BY_HOP && next != IPv6Header.NEXT_ROUTING &&
                next != IPv6Header.NEXT_DESTINATION && next != IPv6Header.NEXT_AH) {
                return null
            }
            if (++extCount > 8 || extBytes > 256 || offset + 2 > total) return null
            val len = if (next == IPv6Header.NEXT_AH) {
                val units = packet[offset + 1].toInt() and 0xFF
                (units + 2) * 4
            } else {
                (u8(packet[offset + 1]) + 1) * 8
            }
            if (len < 8 || offset + len > total) return null
            next = packet[offset].toInt() and 0xFF
            offset += len
            extBytes += len
        }

        if (offset + FRAGMENT_HEADER_LENGTH > total) return null

        val followingHeader = packet[offset].toInt() and 0xFF
        if (followingHeader != IPv6Header.PROTOCOL_TCP &&
            followingHeader != IPv6Header.PROTOCOL_UDP &&
            followingHeader != IPv6Header.PROTOCOL_ICMPV6) {
            return null
        }

        val field = u16(packet, offset + 2)
        val fragmentOffset = (field ushr 3) * 8
        val more = (field and 0x1) != 0
        val identification = u32(packet, offset + 4)
        val fragmentPayloadLength = total - (offset + FRAGMENT_HEADER_LENGTH)
        if (fragmentPayloadLength < 0 || fragmentPayloadLength > MAX_FRAGMENT_PAYLOAD) return null
        if (more && (fragmentPayloadLength % 8 != 0)) return null
        if (fragmentOffset + fragmentPayloadLength > (MAX_REASSEMBLED_PACKET - offset)) return null

        val key = Key(packet.copyOfRange(8, 24), packet.copyOfRange(24, 40), identification)
        val existing = entries[key]
        val prefix = packet.copyOfRange(0, offset)
        val entry = existing ?: Entry(
            key = key,
            prefix = prefix,
            fragmentHeaderOffset = offset,
            nextHeader = followingHeader,
            createdAtMs = now
        )

        if (entry.fragmentHeaderOffset != offset || entry.nextHeader != followingHeader ||
            !entry.prefix.contentEquals(prefix)) {
            entries.remove(key)
            return null
        }

        if (entry.fragments.size >= MAX_FRAGMENTS_PER_ENTRY) {
            entries.remove(key)
            return null
        }

        val payload = packet.copyOfRange(offset + FRAGMENT_HEADER_LENGTH, total)
        val newRangeStart = fragmentOffset
        val newRangeEnd = fragmentOffset + payload.size
        for (f in entry.fragments) {
            val start = f.offset
            val end = f.offset + f.payload.size
            if (newRangeStart < end && start < newRangeEnd) {
                // Overlaps are rejected rather than trying to resolve ambiguity.
                entries.remove(key)
                return null
            }
        }

        entry.fragments.add(Fragment(fragmentOffset, payload, more))
        if (!more) {
            entry.totalPayloadLength = newRangeEnd
        } else if (entry.totalPayloadLength != null && newRangeEnd > entry.totalPayloadLength!!) {
            entries.remove(key)
            return null
        }

        // Duplicate fragment offset is also an overlap in our model, already rejected above.
        entries[key] = entry

        val totalPayload = entry.totalPayloadLength ?: return null
        val fragmentsSorted = entry.fragments.sortedBy { it.offset }
        var cursor = 0
        for (f in fragmentsSorted) {
            if (f.offset != cursor) return null
            cursor += f.payload.size
        }
        if (cursor != totalPayload) return null

        val unfragmentableLength = entry.fragmentHeaderOffset - IPv6Header.BASE_HEADER_LENGTH
        val reconstructedPayloadLength = unfragmentableLength + totalPayload
        val reassembledLength = IPv6Header.BASE_HEADER_LENGTH + reconstructedPayloadLength
        if (reassembledLength > MAX_REASSEMBLED_PACKET || reconstructedPayloadLength > 0xFFFF) {
            entries.remove(key)
            return null
        }

        val out = ByteArray(reassembledLength)
        System.arraycopy(entry.prefix, 0, out, 0, entry.fragmentHeaderOffset)
        for (f in fragmentsSorted) {
            System.arraycopy(f.payload, 0, out, entry.fragmentHeaderOffset + f.offset, f.payload.size)
        }
        putU16(out, 4, reconstructedPayloadLength)
        out[6] = entry.nextHeader.toByte()
        entries.remove(key)
        return out
    }

    @Synchronized
    fun clear() = entries.clear()

    private fun purgeExpired(now: Long) {
        val iterator = entries.entries.iterator()
        while (iterator.hasNext()) {
            val e = iterator.next().value
            if (now - e.createdAtMs > TIMEOUT_MS) iterator.remove()
        }
    }

    private fun u8(b: Byte): Int = b.toInt() and 0xFF
    private fun u16(d: ByteArray, o: Int): Int = (u8(d[o]) shl 8) or u8(d[o + 1])
    private fun u32(d: ByteArray, o: Int): Long =
        ((u8(d[o]).toLong() shl 24) or
            (u8(d[o + 1]).toLong() shl 16) or
            (u8(d[o + 2]).toLong() shl 8) or
            u8(d[o + 3]).toLong())

    private fun putU16(d: ByteArray, o: Int, v: Int) {
        d[o] = (v ushr 8).toByte()
        d[o + 1] = v.toByte()
    }
}
