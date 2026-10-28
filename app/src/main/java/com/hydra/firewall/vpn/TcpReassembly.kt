package com.hydra.firewall.vpn

/**
 * Small bounded TCP receive-side reassembly buffer for data arriving from the
 * TUN/app side out of order. It is deliberately independent from sockets/UI so
 * it can be unit-tested without Android.
 *
 * The buffer only accepts sequence ranges reasonably close to [expectedSeq].
 * It is not intended to model the complete TCP receive window; the forwarding
 * engine remains responsible for advertising the real receive window.
 */
class TcpReassembly(
    private val maxSegments: Int = 64,
    private val maxBytes: Int = 64 * 1024,
    private val maxAhead: Int = 64 * 1024
) {
    data class Segment(val sequence: Long, val payload: ByteArray)

    enum class ResultType { ACCEPTED, DUPLICATE, OUT_OF_WINDOW, OVERFLOW }

    data class Result(
        val type: ResultType,
        val delivered: List<ByteArray>,
        val nextExpected: Long,
        val bufferedBytes: Int
    )

    private val segments = mutableListOf<Segment>()
    private var bytesBuffered = 0

    fun clear() {
        segments.clear()
        bytesBuffered = 0
    }

    fun bufferedBytes(): Int = bytesBuffered
    fun segmentCount(): Int = segments.size

    fun offer(sequence: Long, payload: ByteArray, expectedSeq: Long): Result {
        if (payload.isEmpty()) {
            return Result(ResultType.ACCEPTED, emptyList(), expectedSeq, bytesBuffered)
        }

        var seq = sequence and 0xFFFF_FFFFL
        var data = payload
        val end = TcpSequence.add(seq, data.size.toLong())

        // Entirely duplicate/old data.
        if (TcpSequence.compare(end, expectedSeq) <= 0) {
            return Result(ResultType.DUPLICATE, emptyList(), expectedSeq, bytesBuffered)
        }

        // Trim already-delivered prefix.
        if (TcpSequence.compare(seq, expectedSeq) < 0) {
            val trim = TcpSequence.distance(seq, expectedSeq).toInt()
            if (trim >= data.size) {
                return Result(ResultType.DUPLICATE, emptyList(), expectedSeq, bytesBuffered)
            }
            data = data.copyOfRange(trim, data.size)
            seq = expectedSeq
        }

        val ahead = TcpSequence.distance(expectedSeq, seq)
        if (ahead > maxAhead.toLong()) {
            return Result(ResultType.OUT_OF_WINDOW, emptyList(), expectedSeq, bytesBuffered)
        }

        // Merge/ignore overlaps with already buffered ranges. The buffers are
        // intentionally small, so a bounded linear scan is preferable to a
        // more complicated sequence-tree implementation here.
        val incoming = Segment(seq, data)
        val previousSegments = segments.toList()
        val previousBytes = bytesBuffered
        val merged = mergeIncoming(incoming)
        if (!merged) {
            return Result(ResultType.DUPLICATE, emptyList(), expectedSeq, bytesBuffered)
        }

        if (segments.size > maxSegments || bytesBuffered > maxBytes) {
            // Revert atomically and fail closed.
            segments.clear()
            segments.addAll(previousSegments)
            bytesBuffered = previousBytes
            return Result(ResultType.OVERFLOW, emptyList(), expectedSeq, bytesBuffered)
        }

        var next = expectedSeq
        val delivered = ArrayList<ByteArray>()
        while (true) {
            val index = segments.indexOfFirst { TcpSequence.compare(it.sequence, next) == 0 }
            if (index < 0) break
            val segment = segments.removeAt(index)
            bytesBuffered -= segment.payload.size
            delivered += segment.payload
            next = TcpSequence.add(next, segment.payload.size.toLong())
        }
        return Result(ResultType.ACCEPTED, delivered, next, bytesBuffered)
    }

    private fun mergeIncoming(incoming: Segment): Boolean {
        var newSeq = incoming.sequence
        var newData = incoming.payload
        val remove = ArrayList<Segment>()

        for (existing in segments) {
            if (rangesTouchOrOverlap(newSeq, newData.size, existing.sequence, existing.payload.size)) {
                val mergedStart = if (TcpSequence.compare(newSeq, existing.sequence) <= 0) newSeq else existing.sequence
                val mergedEnd = maxEnd(mergedStart, newSeq, newData.size, existing.sequence, existing.payload.size)
                val mergedLength = TcpSequence.distance(mergedStart, mergedEnd).toInt()
                if (mergedLength <= 0 || mergedLength > maxBytes) continue
                val mergedBytes = ByteArray(mergedLength)
                copyInto(mergedBytes, mergedStart, newSeq, newData)
                copyInto(mergedBytes, mergedStart, existing.sequence, existing.payload)
                newSeq = mergedStart
                newData = mergedBytes
                remove += existing
            }
        }

        if (remove.isEmpty() && segments.any { it.sequence == newSeq && it.payload.contentEquals(newData) }) {
            return false
        }

        remove.forEach {
            segments.remove(it)
            bytesBuffered -= it.payload.size
        }
        segments += Segment(newSeq, newData)
        bytesBuffered += newData.size
        segments.sortWith(Comparator { a, b ->
            val da = TcpSequence.distance(incoming.sequence, a.sequence)
            val db = TcpSequence.distance(incoming.sequence, b.sequence)
            da.compareTo(db)
        })
        return true
    }

    private fun rangesTouchOrOverlap(aSeq: Long, aLen: Int, bSeq: Long, bLen: Int): Boolean {
        val aEnd = TcpSequence.add(aSeq, aLen.toLong())
        val bEnd = TcpSequence.add(bSeq, bLen.toLong())
        return TcpSequence.compare(aSeq, bEnd) <= 0 && TcpSequence.compare(bSeq, aEnd) <= 0
    }

    private fun maxEnd(base: Long, aSeq: Long, aLen: Int, bSeq: Long, bLen: Int): Long {
        val aEnd = TcpSequence.add(aSeq, aLen.toLong())
        val bEnd = TcpSequence.add(bSeq, bLen.toLong())
        val da = TcpSequence.distance(base, aEnd)
        val db = TcpSequence.distance(base, bEnd)
        return if (da >= db) aEnd else bEnd
    }

    private fun copyInto(dest: ByteArray, base: Long, sequence: Long, payload: ByteArray) {
        val offset = TcpSequence.distance(base, sequence).toInt()
        if (offset < 0 || offset >= dest.size) return
        val count = minOf(payload.size, dest.size - offset)
        payload.copyInto(dest, offset, 0, count)
    }
}
