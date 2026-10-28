package com.hydra.firewall.vpn

/**
 * JSON mínimo en Kotlin puro (Map / List / String / Boolean / Long / Double / null).
 *
 * Se usa para exportar/importar configuración sin depender de org.json: en los tests unitarios JVM
 * de Android, org.json está "stubbed" y devuelve valores por defecto, lo que haría los tests inútiles.
 */
object MiniJson {
    private const val MAX_DEPTH = 64

    fun write(value: Any?, pretty: Boolean = false): String =
        StringBuilder().also { writeValue(it, value, pretty, 0) }.toString()

    private fun writeValue(sb: StringBuilder, v: Any?, pretty: Boolean, depth: Int) {
        when (v) {
            null -> sb.append("null")
            is Boolean -> sb.append(if (v) "true" else "false")
            is Int -> sb.append(v)
            is Long -> sb.append(v)
            is Double -> {
                require(!v.isNaN() && !v.isInfinite()) { "json: número no finito" }
                sb.append(v)
            }
            is Float -> writeValue(sb, v.toDouble(), pretty, depth)
            is String -> writeString(sb, v)
            is Map<*, *> -> {
                if (v.isEmpty()) { sb.append("{}"); return }
                sb.append('{')
                var first = true
                for ((k, value) in v) {
                    if (!first) sb.append(',')
                    first = false
                    newline(sb, pretty, depth + 1)
                    writeString(sb, k.toString())
                    sb.append(if (pretty) ": " else ":")
                    writeValue(sb, value, pretty, depth + 1)
                }
                newline(sb, pretty, depth)
                sb.append('}')
            }
            is Iterable<*> -> {
                val items = v.toList()
                if (items.isEmpty()) { sb.append("[]"); return }
                sb.append('[')
                items.forEachIndexed { i, item ->
                    if (i > 0) sb.append(',')
                    newline(sb, pretty, depth + 1)
                    writeValue(sb, item, pretty, depth + 1)
                }
                newline(sb, pretty, depth)
                sb.append(']')
            }
            else -> throw IllegalArgumentException("json: tipo no soportado ${v.javaClass.simpleName}")
        }
    }

    private fun newline(sb: StringBuilder, pretty: Boolean, depth: Int) {
        if (!pretty) return
        sb.append('\n')
        repeat(depth) { sb.append("  ") }
    }

    private fun writeString(sb: StringBuilder, s: String) {
        sb.append('"')
        for (c in s) {
            when {
                c == '"' -> sb.append("\\\"")
                c == '\\' -> sb.append("\\\\")
                c == '\n' -> sb.append("\\n")
                c == '\r' -> sb.append("\\r")
                c == '\t' -> sb.append("\\t")
                c.code < 0x20 -> sb.append("\\u").append(c.code.toString(16).padStart(4, '0'))
                else -> sb.append(c)
            }
        }
        sb.append('"')
    }

    /** @throws IllegalArgumentException si el texto no es JSON válido. */
    fun parse(text: String): Any? {
        val p = Parser(text)
        p.skipWs()
        val v = p.readValue(0)
        p.skipWs()
        require(p.atEnd()) { "json: texto extra en posición ${p.pos}" }
        return v
    }

    private class Parser(private val s: String) {
        var pos = 0
        fun atEnd() = pos >= s.length

        fun skipWs() {
            while (pos < s.length && (s[pos] == ' ' || s[pos] == '\n' || s[pos] == '\r' || s[pos] == '\t')) pos++
        }

        private fun fail(msg: String): Nothing = throw IllegalArgumentException("json: $msg en posición $pos")

        fun readValue(depth: Int): Any? {
            if (depth > MAX_DEPTH) fail("anidación excesiva")
            if (atEnd()) fail("fin inesperado")
            return when (val c = s[pos]) {
                '{' -> readObject(depth)
                '[' -> readArray(depth)
                '"' -> readString()
                't' -> literal("true", true)
                'f' -> literal("false", false)
                'n' -> literal("null", null)
                else -> if (c == '-' || c in '0'..'9') readNumber() else fail("carácter inesperado '$c'")
            }
        }

        private fun literal(word: String, value: Any?): Any? {
            if (!s.startsWith(word, pos)) fail("literal inválido")
            pos += word.length
            return value
        }

        private fun readObject(depth: Int): Map<String, Any?> {
            pos++ // {
            val out = LinkedHashMap<String, Any?>()
            skipWs()
            if (pos < s.length && s[pos] == '}') { pos++; return out }
            while (true) {
                skipWs()
                if (atEnd() || s[pos] != '"') fail("se esperaba una clave")
                val key = readString()
                skipWs()
                if (atEnd() || s[pos] != ':') fail("se esperaba ':'")
                pos++
                skipWs()
                out[key] = readValue(depth + 1)
                skipWs()
                if (atEnd()) fail("objeto sin cerrar")
                when (s[pos]) {
                    ',' -> pos++
                    '}' -> { pos++; return out }
                    else -> fail("se esperaba ',' o '}'")
                }
            }
        }

        private fun readArray(depth: Int): List<Any?> {
            pos++ // [
            val out = ArrayList<Any?>()
            skipWs()
            if (pos < s.length && s[pos] == ']') { pos++; return out }
            while (true) {
                skipWs()
                out += readValue(depth + 1)
                skipWs()
                if (atEnd()) fail("arreglo sin cerrar")
                when (s[pos]) {
                    ',' -> pos++
                    ']' -> { pos++; return out }
                    else -> fail("se esperaba ',' o ']'")
                }
            }
        }

        private fun readString(): String {
            pos++ // "
            val sb = StringBuilder()
            while (true) {
                if (atEnd()) fail("cadena sin cerrar")
                val c = s[pos++]
                when {
                    c == '"' -> return sb.toString()
                    c == '\\' -> {
                        if (atEnd()) fail("escape incompleto")
                        when (val e = s[pos++]) {
                            '"' -> sb.append('"')
                            '\\' -> sb.append('\\')
                            '/' -> sb.append('/')
                            'b' -> sb.append('\b')
                            'f' -> sb.append('\u000C')
                            'n' -> sb.append('\n')
                            'r' -> sb.append('\r')
                            't' -> sb.append('\t')
                            'u' -> {
                                if (pos + 4 > s.length) fail("\\u incompleto")
                                val hex = s.substring(pos, pos + 4)
                                val code = hex.toIntOrNull(16) ?: fail("\\u inválido")
                                sb.append(code.toChar())
                                pos += 4
                            }
                            else -> fail("escape inválido '\\$e'")
                        }
                    }
                    c.code < 0x20 -> fail("carácter de control en cadena")
                    else -> sb.append(c)
                }
            }
        }

        private fun readNumber(): Any {
            val start = pos
            if (s[pos] == '-') pos++
            while (pos < s.length && s[pos] in '0'..'9') pos++
            var isDouble = false
            if (pos < s.length && s[pos] == '.') {
                isDouble = true; pos++
                while (pos < s.length && s[pos] in '0'..'9') pos++
            }
            if (pos < s.length && (s[pos] == 'e' || s[pos] == 'E')) {
                isDouble = true; pos++
                if (pos < s.length && (s[pos] == '+' || s[pos] == '-')) pos++
                while (pos < s.length && s[pos] in '0'..'9') pos++
            }
            val raw = s.substring(start, pos)
            if (raw == "-" || raw.isEmpty()) fail("número inválido")
            return if (isDouble) (raw.toDoubleOrNull() ?: fail("número inválido"))
            else (raw.toLongOrNull() ?: fail("entero fuera de rango"))
        }
    }
}
