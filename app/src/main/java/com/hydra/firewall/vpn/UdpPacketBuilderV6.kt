package com.hydra.firewall.vpn

import java.net.Inet6Address

/** Builds IPv6/UDP packets injected toward the application-facing TUN. */
object UdpPacketBuilderV6 {
    private const val IP_HEADER=40
    private const val UDP_HEADER=8
    fun build(source: java.net.InetAddress, destination: java.net.InetAddress, sourcePort:Int, destinationPort:Int, payload:ByteArray):ByteArray{
        val src=source as? Inet6Address ?: throw IllegalArgumentException("IPv6 source required")
        val dst=destination as? Inet6Address ?: throw IllegalArgumentException("IPv6 destination required")
        val total=IP_HEADER+UDP_HEADER+payload.size
        require(total <= 65575)
        val p=ByteArray(total)
        p[0]=0x60; p[6]=17; p[7]=64
        putU16(p,4,UDP_HEADER+payload.size)
        System.arraycopy(src.address,0,p,8,16); System.arraycopy(dst.address,0,p,24,16)
        val u=IP_HEADER
        putU16(p,u,sourcePort); putU16(p,u+2,destinationPort); putU16(p,u+4,UDP_HEADER+payload.size); putU16(p,u+6,0)
        if(payload.isNotEmpty()) System.arraycopy(payload,0,p,u+UDP_HEADER,payload.size)
        val pseudo=ByteArray(40)
        System.arraycopy(src.address,0,pseudo,0,16); System.arraycopy(dst.address,0,pseudo,16,16)
        putU32(pseudo,32,UDP_HEADER+payload.size.toLong()); pseudo[39]=17
        var sum=InternetChecksum.compute(pseudo); sum=InternetChecksum.add(sum,p,u,UDP_HEADER+payload.size)
        var c=(sum xor 0xFFFF) and 0xFFFF; if(c==0)c=0xFFFF; putU16(p,u+6,c)
        return p
    }
    private fun putU16(d:ByteArray,o:Int,v:Int){d[o]=(v ushr 8).toByte();d[o+1]=v.toByte()}
    private fun putU32(d:ByteArray,o:Int,v:Long){d[o]=(v ushr 24).toByte();d[o+1]=(v ushr 16).toByte();d[o+2]=(v ushr 8).toByte();d[o+3]=v.toByte()}
}
