package com.hydra.firewall.vpn

import java.net.Inet6Address

/** Builds IPv6/TCP packets injected toward the application-facing TUN. */
object TcpPacketBuilderV6 {
    private const val IP_HEADER = 40
    private const val TCP_HEADER = 20
    private const val FLAG_FIN = 0x01
    private const val FLAG_SYN = 0x02
    private const val FLAG_RST = 0x04
    private const val FLAG_PSH = 0x08
    private const val FLAG_ACK = 0x10

    fun build(
        session: TcpSession,
        seq: Long,
        ack: Long,
        syn: Boolean = false,
        ackFlag: Boolean = true,
        fin: Boolean = false,
        rst: Boolean = false,
        psh: Boolean = false,
        payload: ByteArray = ByteArray(0)
    ): ByteArray {
        val src = session.key.dstAddr as? Inet6Address ?: throw IllegalArgumentException("IPv6 source required")
        val dst = session.key.srcAddr as? Inet6Address ?: throw IllegalArgumentException("IPv6 destination required")
        val options = if (syn) byteArrayOf(2,4,
            ((session.localMss ushr 8) and 0xFF).toByte(), (session.localMss and 0xFF).toByte(),
            3,3,0,0) else ByteArray(0)
        val tcpLen = TCP_HEADER + options.size
        val total = IP_HEADER + tcpLen + payload.size
        require(total <= 65575)
        val p = ByteArray(total)
        p[0] = 0x60
        p[6] = 6
        p[7] = 64
        putU16(p, 4, tcpLen + payload.size)
        System.arraycopy(src.address, 0, p, 8, 16)
        System.arraycopy(dst.address, 0, p, 24, 16)
        val t = IP_HEADER
        putU16(p, t, session.key.dstPort); putU16(p, t+2, session.key.srcPort)
        putU32(p, t+4, seq); putU32(p, t+8, ack)
        p[t+12] = ((tcpLen/4) shl 4).toByte()
        p[t+13] = ((if(fin) FLAG_FIN else 0) or (if(syn) FLAG_SYN else 0) or (if(rst) FLAG_RST else 0) or (if(psh) FLAG_PSH else 0) or (if(ackFlag) FLAG_ACK else 0)).toByte()
        putU16(p, t+14, session.advertisedReceiveWindow()); putU16(p,t+16,0); putU16(p,t+18,0)
        if(options.isNotEmpty()) System.arraycopy(options,0,p,t+TCP_HEADER,options.size)
        if(payload.isNotEmpty()) System.arraycopy(payload,0,p,t+tcpLen,payload.size)
        val pseudo = ByteArray(40)
        System.arraycopy(src.address,0,pseudo,0,16); System.arraycopy(dst.address,0,pseudo,16,16)
        putU32(pseudo,32,tcpLen+payload.size.toLong()); pseudo[39]=6
        var sum = InternetChecksum.compute(pseudo)
        sum = InternetChecksum.add(sum,p,t,tcpLen+payload.size)
        putU16(p,t+16,(sum xor 0xFFFF) and 0xFFFF)
        return p
    }
    private fun putU16(d:ByteArray,o:Int,v:Int){d[o]=(v ushr 8).toByte();d[o+1]=v.toByte()}
    private fun putU32(d:ByteArray,o:Int,v:Long){d[o]=(v ushr 24).toByte();d[o+1]=(v ushr 16).toByte();d[o+2]=(v ushr 8).toByte();d[o+3]=v.toByte()}
}
