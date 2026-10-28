package com.hydra.firewall.vpn

/** RFC 1071-style one's-complement checksum helpers. */
object InternetChecksum {
    fun compute(data: ByteArray, offset: Int = 0, length: Int = data.size - offset): Int {
        require(offset >= 0 && length >= 0 && offset + length <= data.size)
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            sum = (sum and 0xFFFF) + (sum ushr 16)
            i += 2
        }
        if (i < end) {
            sum += (data[i].toInt() and 0xFF) shl 8
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        while (sum ushr 16 != 0L) {
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        return sum.toInt() and 0xFFFF
    }

    fun checksum(data: ByteArray, offset: Int = 0, length: Int = data.size - offset): Int =
        (compute(data, offset, length) xor 0xFFFF) and 0xFFFF

    fun add(accumulator: Int, data: ByteArray, offset: Int = 0, length: Int = data.size - offset): Int {
        var sum = accumulator.toLong() and 0xFFFF
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += ((data[i].toInt() and 0xFF) shl 8) or (data[i + 1].toInt() and 0xFF)
            sum = (sum and 0xFFFF) + (sum ushr 16)
            i += 2
        }
        if (i < end) {
            sum += (data[i].toInt() and 0xFF) shl 8
            sum = (sum and 0xFFFF) + (sum ushr 16)
        }
        while (sum ushr 16 != 0L) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.toInt() and 0xFFFF
    }
}
