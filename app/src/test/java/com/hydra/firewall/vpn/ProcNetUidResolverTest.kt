package com.hydra.firewall.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.net.InetAddress
import java.nio.file.Files

class ProcNetUidResolverTest {
    @Test
    fun readsActualUidColumnAndUsesUniqueLocalEndpointFallback() {
        val file = Files.createTempFile("proc-net", ".txt").toFile()
        try {
            file.writeText(
                """
                sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
                 0: 0200000A:9CBB 04030201:01BB 01 00000000:00000000 00:00000000 00000000 10042        0 123 1 0000000000000000 20 4 30 10 -1
                """.trimIndent()
            )

            assertEquals(10042, invoke(file.absolutePath, "10.0.0.2", 0x9CBB, "1.2.3.4", 443))
            assertEquals(10042, invoke(file.absolutePath, "10.0.0.2", 0x9CBB, "9.9.9.9", 443))

            file.appendText(
                "\n 1: 0200000A:9CBB 05050505:01BB 01 00000000:00000000 00:00000000 00000000 10043        0 124 1 0000000000000000 20 4 30 10 -1\n"
            )
            assertNull(invoke(file.absolutePath, "10.0.0.2", 0x9CBB, "8.8.8.8", 443))
        } finally {
            file.delete()
        }
    }

    private fun invoke(path: String, src: String, sport: Int, dst: String, dport: Int): Int? {
        val method = ProcNetUidResolver::class.java.declaredMethods.first {
            it.name == "resolveSub" &&
                it.parameterTypes.size == 6 &&
                it.parameterTypes[1] == ByteArray::class.java
        }
        method.isAccessible = true
        return method.invoke(
            ProcNetUidResolver,
            UidResolver.PROTOCOL_TCP,
            InetAddress.getByName(src).address,
            sport,
            InetAddress.getByName(dst).address,
            dport,
            path
        ) as Int?
    }
}
