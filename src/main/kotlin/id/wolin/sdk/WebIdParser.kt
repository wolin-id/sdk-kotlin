package id.wolin.sdk

import java.net.URI

/**
 * RDF Object Term representation for W3C Turtle / N-Triples triples.
 */
sealed interface RdfTerm {
    data class Iri(val value: String) : RdfTerm
    data class BlankNode(val id: String) : RdfTerm
    data class Literal(
        val lexicalForm: String,
        val datatype: String? = null,
        val language: String? = null,
    ) : RdfTerm
}

/**
 * Single RDF Triple (`subject predicate object`).
 */
data class RdfTriple(
    val subject: String,
    val predicate: String,
    val obj: RdfTerm,
)

/**
 * Parsed W3C Solid WebID Profile Document metadata.
 */
data class WebIdProfile(
    val webId: String,
    val storages: List<String>,
    val oidcIssuers: List<String>,
    val inboxes: List<String>,
    val types: List<String>,
    val triples: List<RdfTriple> = emptyList(),
) {
    /** Primary `pim:storage` root IRI declared on this WebID, if any. */
    val primaryStorage: String?
        get() = storages.firstOrNull()

    /** Verifies W3C Solid-OIDC trust chain (`<webId> solid:oidcIssuer <expectedIssuer>`). */
    fun verifyOidcIssuer(expectedIssuer: String): Boolean {
        val trimmed = expectedIssuer.trim()
        return trimmed.isNotEmpty() && oidcIssuers.any { it == trimmed }
    }
}

/**
 * Pure Kotlin stdlib W3C Turtle & N-Triples parser tailored for Solid WebID Profiles,
 * `pim:storage` discovery, `solid:oidcIssuer` verification, and LDP Container graphs.
 */
object WebIdParser {
    const val RDF_TYPE = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
    const val RDF_FIRST = "http://www.w3.org/1999/02/22-rdf-syntax-ns#first"
    const val RDF_REST = "http://www.w3.org/1999/02/22-rdf-syntax-ns#rest"
    const val RDF_NIL = "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil"
    const val XSD_STRING = "http://www.w3.org/2001/XMLSchema#string"
    const val XSD_BOOLEAN = "http://www.w3.org/2001/XMLSchema#boolean"
    const val XSD_INTEGER = "http://www.w3.org/2001/XMLSchema#integer"
    const val XSD_DECIMAL = "http://www.w3.org/2001/XMLSchema#decimal"
    const val XSD_DOUBLE = "http://www.w3.org/2001/XMLSchema#double"
    const val LANG_STRING = "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString"

    const val PIM_STORAGE = "http://www.w3.org/ns/pim/space#storage"
    const val PIM_STORAGE_CLASS = "http://www.w3.org/ns/pim/space#Storage"
    const val SOLID_OIDC_ISSUER = "http://www.w3.org/ns/solid/terms#oidcIssuer"
    const val LDP_INBOX = "http://www.w3.org/ns/ldp#inbox"
    const val LDP_CONTAINS = "http://www.w3.org/ns/ldp#contains"
    const val FOAF_PERSON = "http://xmlns.com/foaf/0.1/Person"
    const val FOAF_PRIMARY_TOPIC = "http://xmlns.com/foaf/0.1/primaryTopic"

    private const val MAX_PROFILE_CHARS = 512 * 1024

    /**
     * Parses a W3C Turtle / N-Triples WebID Profile document and extracts `pim:storage`,
     * `solid:oidcIssuer`, `ldp:inbox`, and `rdf:type` triples for [webId].
     */
    @JvmStatic
    @JvmOverloads
    fun parseTurtle(
        turtle: String,
        webId: String,
        baseIri: String = webId.substringBefore('#'),
    ): WebIdProfile {
        if (webId.isBlank()) {
            throw WolinException("WebID URI must not be blank")
        }
        if (turtle.length > MAX_PROFILE_CHARS) {
            throw WolinException("WebID Profile RDF payload exceeds maximum allowed size")
        }

        val triples = parseTriples(turtle, baseIri)
        val storages = linkedSetOf<String>()
        val oidcIssuers = linkedSetOf<String>()
        val inboxes = linkedSetOf<String>()
        val types = linkedSetOf<String>()

        for (triple in triples) {
            if (triple.subject != webId) continue
            val objIri = (triple.obj as? RdfTerm.Iri)?.value ?: continue
            when (triple.predicate) {
                PIM_STORAGE -> storages.add(objIri)
                SOLID_OIDC_ISSUER -> oidcIssuers.add(objIri)
                LDP_INBOX -> inboxes.add(objIri)
                RDF_TYPE -> types.add(objIri)
            }
        }

        return WebIdProfile(
            webId = webId,
            storages = storages.toList(),
            oidcIssuers = oidcIssuers.toList(),
            inboxes = inboxes.toList(),
            types = types.toList(),
            triples = triples,
        )
    }

    /**
     * Parses a W3C Turtle or N-Triples document into a list of resolved [RdfTriple]s.
     */
    @JvmStatic
    fun parseTriples(turtle: String, baseIri: String): List<RdfTriple> {
        val tokens = TurtleLexer(turtle).tokenize()
        return TurtleGrammar(tokens, baseIri).parseDocument()
    }

    /**
     * Resolves a potentially relative IRI against [baseIri] according to RFC 3986 §5.2
     * (preserving `<>` as the document IRI without fragment, and `<#frag>` against the document IRI).
     */
    @JvmStatic
    fun resolveIri(raw: String, baseIri: String): String {
        val docBase = baseIri.substringBefore('#')
        if (raw.isEmpty()) return docBase
        if (raw.startsWith('#')) return "$docBase$raw"
        if (raw.startsWith('?')) return "${docBase.substringBefore('?')}$raw"

        val candidate = try {
            URI(raw)
        } catch (e: Exception) {
            throw WolinException("Malformed IRI '$raw': ${e.message}", e)
        }
        if (candidate.isAbsolute) return raw

        return try {
            URI(docBase).resolve(candidate).toString()
        } catch (e: Exception) {
            throw WolinException("Failed to resolve IRI '$raw' against base '$docBase': ${e.message}", e)
        }
    }

    private sealed interface Token {
        data object Dot : Token
        data object Semicolon : Token
        data object Comma : Token
        data object LBracket : Token
        data object RBracket : Token
        data object LParen : Token
        data object RParen : Token
        data object AtPrefix : Token
        data object AtBase : Token
        data object SparqlPrefix : Token
        data object SparqlBase : Token
        data object KeywordA : Token
        data class IriRef(val raw: String) : Token
        data class PName(val prefix: String, val local: String) : Token
        data class BlankNodeLabel(val label: String) : Token
        data class StringLit(
            val value: String,
            val language: String?,
            val datatypeToken: Token?,
        ) : Token
        data class PlainLit(val lexical: String, val datatypeIri: String) : Token
    }

    private class TurtleLexer(private val input: String) {
        private var pos = 0
        private val len = input.length

        fun tokenize(): List<Token> {
            val tokens = ArrayList<Token>()
            while (pos < len) {
                skipWhitespaceAndComments()
                if (pos >= len) break

                when (val ch = input[pos]) {
                    '[' -> {
                        pos++
                        tokens.add(Token.LBracket)
                    }
                    ']' -> {
                        pos++
                        tokens.add(Token.RBracket)
                    }
                    '(' -> {
                        pos++
                        tokens.add(Token.LParen)
                    }
                    ')' -> {
                        pos++
                        tokens.add(Token.RParen)
                    }
                    ';' -> {
                        pos++
                        tokens.add(Token.Semicolon)
                    }
                    ',' -> {
                        pos++
                        tokens.add(Token.Comma)
                    }
                    '.' -> {
                        if (pos + 1 < len && input[pos + 1].isDigit()) {
                            tokens.add(readNumberLiteral())
                        } else {
                            pos++
                            tokens.add(Token.Dot)
                        }
                    }
                    '<' -> tokens.add(readIriRef())
                    '"', '\'' -> tokens.add(readStringLiteral())
                    '@' -> tokens.add(readAtDirective())
                    '+', '-' -> tokens.add(readNumberLiteral())
                    else -> when {
                        ch.isDigit() -> tokens.add(readNumberLiteral())
                        ch == '_' && pos + 1 < len && input[pos + 1] == ':' -> tokens.add(readBlankNodeLabel())
                        else -> tokens.add(readWordOrPrefixedName())
                    }
                }
            }
            return tokens
        }

        private fun skipWhitespaceAndComments() {
            while (pos < len) {
                val ch = input[pos]
                if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n') {
                    pos++
                } else if (ch == '#') {
                    while (pos < len && input[pos] != '\n' && input[pos] != '\r') {
                        pos++
                    }
                } else {
                    break
                }
            }
        }

        private fun readIriRef(): Token.IriRef {
            pos++ // consume '<'
            val sb = StringBuilder()
            while (pos < len) {
                val ch = input[pos++]
                when {
                    ch == '>' -> return Token.IriRef(sb.toString())
                    ch == '\\' -> sb.append(readUnicodeEscapeOnly())
                    ch.code <= 0x20 || ch == '<' || ch == '"' || ch == '{' || ch == '}' || ch == '|' || ch == '^' || ch == '`' -> {
                        throw WolinException("Disallowed character '$ch' inside Turtle IRIREF")
                    }
                    else -> sb.append(ch)
                }
            }
            throw WolinException("Unterminated '<...>' IRIREF in Turtle document")
        }

        private fun readStringLiteral(): Token.StringLit {
            val quote = input[pos]
            val isLong = pos + 2 < len && input[pos + 1] == quote && input[pos + 2] == quote
            pos += if (isLong) 3 else 1

            val sb = StringBuilder()
            var closed = false
            while (pos < len) {
                if (isLong && pos + 2 < len && input[pos] == quote && input[pos + 1] == quote && input[pos + 2] == quote) {
                    pos += 3
                    closed = true
                    break
                }
                if (!isLong && input[pos] == quote) {
                    pos++
                    closed = true
                    break
                }
                val ch = input[pos++]
                if (!isLong && (ch == '\n' || ch == '\r')) {
                    throw WolinException("Unescaped newline inside single-quoted Turtle literal")
                }
                if (ch == '\\') {
                    sb.append(readStringEscape())
                } else {
                    sb.append(ch)
                }
            }
            if (!closed) {
                throw WolinException("Unterminated string literal in Turtle document")
            }

            var language: String? = null
            var datatypeToken: Token? = null

            if (pos < len && input[pos] == '@') {
                pos++
                val start = pos
                while (pos < len && (input[pos].isLetterOrDigit() || input[pos] == '-')) {
                    pos++
                }
                val tag = input.substring(start, pos)
                if (tag.isEmpty() || tag.startsWith('-') || tag.endsWith('-')) {
                    throw WolinException("Invalid RDF language tag '@$tag'")
                }
                language = tag
            } else if (pos + 1 < len && input[pos] == '^' && input[pos + 1] == '^') {
                pos += 2
                skipWhitespaceAndComments()
                if (pos >= len) {
                    throw WolinException("Missing datatype IRI after '^^' in Turtle literal")
                }
                datatypeToken = if (input[pos] == '<') {
                    readIriRef()
                } else {
                    val tok = readWordOrPrefixedName()
                    if (tok !is Token.PName) {
                        throw WolinException("Invalid datatype after '^^' in Turtle literal")
                    }
                    tok
                }
            }

            return Token.StringLit(sb.toString(), language, datatypeToken)
        }

        private fun readAtDirective(): Token {
            pos++ // consume '@'
            val start = pos
            while (pos < len && input[pos].isLetter()) {
                pos++
            }
            return when (val dir = input.substring(start, pos)) {
                "prefix" -> Token.AtPrefix
                "base" -> Token.AtBase
                else -> throw WolinException("Unknown Turtle directive '@$dir'")
            }
        }

        private fun readBlankNodeLabel(): Token.BlankNodeLabel {
            pos += 2 // consume '_:'
            val sb = StringBuilder()
            while (pos < len) {
                val ch = input[pos]
                if (ch.isLetterOrDigit() || ch == '_' || ch == '-') {
                    sb.append(ch)
                    pos++
                } else if (ch == '.' && pos + 1 < len && (input[pos + 1].isLetterOrDigit() || input[pos + 1] == '_' || input[pos + 1] == '-')) {
                    sb.append(ch)
                    pos++
                } else {
                    break
                }
            }
            if (sb.isEmpty()) {
                throw WolinException("Empty blank node label '_:' in Turtle document")
            }
            return Token.BlankNodeLabel(sb.toString())
        }

        private fun readNumberLiteral(): Token.PlainLit {
            val start = pos
            if (pos < len && (input[pos] == '+' || input[pos] == '-')) {
                pos++
            }
            var hasDigitsBeforeDot = false
            while (pos < len && input[pos].isDigit()) {
                hasDigitsBeforeDot = true
                pos++
            }
            var hasDecimalPoint = false
            if (pos < len && input[pos] == '.') {
                if (pos + 1 < len && (input[pos + 1].isDigit() || input[pos + 1] == 'e' || input[pos + 1] == 'E')) {
                    hasDecimalPoint = true
                    pos++
                    while (pos < len && input[pos].isDigit()) {
                        pos++
                    }
                } else if (!hasDigitsBeforeDot) {
                    throw WolinException("Unexpected '.' in Turtle document")
                }
            }
            var hasExponent = false
            if (pos < len && (input[pos] == 'e' || input[pos] == 'E')) {
                hasExponent = true
                pos++
                if (pos < len && (input[pos] == '+' || input[pos] == '-')) {
                    pos++
                }
                val expStart = pos
                while (pos < len && input[pos].isDigit()) {
                    pos++
                }
                if (pos == expStart) {
                    throw WolinException("Invalid exponent in numeric literal")
                }
            }
            val lex = input.substring(start, pos)
            if (lex == "+" || lex == "-") {
                throw WolinException("Invalid standalone sign '$lex' in Turtle document")
            }
            val dt = when {
                hasExponent -> XSD_DOUBLE
                hasDecimalPoint -> XSD_DECIMAL
                else -> XSD_INTEGER
            }
            return Token.PlainLit(lex, dt)
        }

        private fun readWordOrPrefixedName(): Token {
            val prefixSb = StringBuilder()
            while (pos < len) {
                val ch = input[pos]
                if (ch == ':' || isDelimiter(ch)) break
                prefixSb.append(ch)
                pos++
            }

            if (pos < len && input[pos] == ':') {
                var prefix = prefixSb.toString()
                if (prefix.endsWith('.')) {
                    throw WolinException("Invalid Turtle prefix '$prefix:' ending with '.'")
                }
                pos++ // consume ':'
                val localSb = StringBuilder()
                var lastWasEscaped = false
                val unescapedDotPositions = ArrayList<Int>()

                while (pos < len) {
                    val ch = input[pos]
                    if (ch == '\\') {
                        pos++
                        if (pos >= len) throw WolinException("Trailing backslash in prefixed name")
                        val esc = input[pos++]
                        localSb.append(esc)
                        lastWasEscaped = true
                    } else if (isDelimiter(ch)) {
                        break
                    } else {
                        if (ch == '.') {
                            unescapedDotPositions.add(localSb.length)
                        }
                        localSb.append(ch)
                        pos++
                        lastWasEscaped = false
                    }
                }

                // In Turtle PN_LOCAL, trailing unescaped '.' characters belong to statement punctuation, not the local name.
                while (localSb.isNotEmpty() && !lastWasEscaped && localSb[localSb.length - 1] == '.' &&
                    unescapedDotPositions.contains(localSb.length - 1)
                ) {
                    unescapedDotPositions.removeAt(unescapedDotPositions.size - 1)
                    localSb.setLength(localSb.length - 1)
                    pos--
                }

                return Token.PName(prefix, localSb.toString())
            }

            val word = prefixSb.toString()
            if (word.endsWith('.') && word.length > 1) {
                val trimmed = word.trimEnd('.')
                pos -= (word.length - trimmed.length)
                return classifyKeyword(trimmed)
            }
            return classifyKeyword(word)
        }

        private fun classifyKeyword(word: String): Token =
            when {
                word == "a" -> Token.KeywordA
                word == "true" || word == "false" -> Token.PlainLit(word, XSD_BOOLEAN)
                word.equals("PREFIX", ignoreCase = true) -> Token.SparqlPrefix
                word.equals("BASE", ignoreCase = true) -> Token.SparqlBase
                else -> throw WolinException("Unexpected bare token '$word' in Turtle document")
            }

        private fun isDelimiter(ch: Char): Boolean =
            ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' ||
                ch == ';' || ch == ',' || ch == '[' || ch == ']' ||
                ch == '(' || ch == ')' || ch == '<' || ch == '>' ||
                ch == '"' || ch == '\'' || ch == '#'

        private fun readUnicodeEscapeOnly(): String {
            if (pos >= len) throw WolinException("Unexpected end of input in IRI escape")
            return when (val esc = input[pos++]) {
                'u' -> decodeCodePoint(4)
                'U' -> decodeCodePoint(8)
                else -> throw WolinException("Invalid escape '\\$esc' inside IRIREF")
            }
        }

        private fun readStringEscape(): String {
            if (pos >= len) throw WolinException("Unexpected end of input in string escape")
            return when (val esc = input[pos++]) {
                't' -> "\t"
                'b' -> "\b"
                'n' -> "\n"
                'r' -> "\r"
                'f' -> "\u000C"
                '"' -> "\""
                '\'' -> "'"
                '\\' -> "\\"
                'u' -> decodeCodePoint(4)
                'U' -> decodeCodePoint(8)
                else -> throw WolinException("Invalid escape '\\$esc' in Turtle string literal")
            }
        }

        private fun decodeCodePoint(hexDigits: Int): String {
            if (pos + hexDigits > len) {
                throw WolinException("Truncated Unicode escape in Turtle document")
            }
            val hex = input.substring(pos, pos + hexDigits)
            pos += hexDigits
            val cp = hex.toIntOrNull(16)
                ?: throw WolinException("Invalid hex sequence '$hex' in Unicode escape")
            if (!Character.isValidCodePoint(cp) || cp in 0xD800..0xDFFF) {
                throw WolinException("Invalid Unicode scalar value U+${hex.uppercase()}")
            }
            return String(Character.toChars(cp))
        }
    }

    private class TurtleGrammar(
        private val tokens: List<Token>,
        initialBaseIri: String,
    ) {
        private var idx = 0
        private var currentBase = initialBaseIri.substringBefore('#')
        private val prefixes = HashMap<String, String>()
        private val triples = ArrayList<RdfTriple>()
        private var bnodeCounter = 0

        fun parseDocument(): List<RdfTriple> {
            while (idx < tokens.size) {
                when (peek()) {
                    Token.AtPrefix -> parseAtPrefix()
                    Token.SparqlPrefix -> parseSparqlPrefix()
                    Token.AtBase -> parseAtBase()
                    Token.SparqlBase -> parseSparqlBase()
                    else -> {
                        parseTriplesStatement()
                        expectDot()
                    }
                }
            }
            return triples
        }

        private fun parseAtPrefix() {
            idx++ // @prefix
            val pname = nextToken() as? Token.PName
                ?: throw WolinException("Expected prefix label after '@prefix'")
            if (pname.local.isNotEmpty()) {
                throw WolinException("Invalid prefix declaration '${pname.prefix}:${pname.local}' after '@prefix'")
            }
            val iriTok = nextToken() as? Token.IriRef
                ?: throw WolinException("Expected '<IRI>' in '@prefix' declaration")
            prefixes[pname.prefix] = resolveIri(iriTok.raw, currentBase)
            expectDot()
        }

        private fun parseSparqlPrefix() {
            idx++ // PREFIX
            val pname = nextToken() as? Token.PName
                ?: throw WolinException("Expected prefix label after 'PREFIX'")
            if (pname.local.isNotEmpty()) {
                throw WolinException("Invalid prefix declaration '${pname.prefix}:${pname.local}' after 'PREFIX'")
            }
            val iriTok = nextToken() as? Token.IriRef
                ?: throw WolinException("Expected '<IRI>' in 'PREFIX' declaration")
            prefixes[pname.prefix] = resolveIri(iriTok.raw, currentBase)
        }

        private fun parseAtBase() {
            idx++ // @base
            val iriTok = nextToken() as? Token.IriRef
                ?: throw WolinException("Expected '<IRI>' after '@base'")
            currentBase = resolveIri(iriTok.raw, currentBase)
            expectDot()
        }

        private fun parseSparqlBase() {
            idx++ // BASE
            val iriTok = nextToken() as? Token.IriRef
                ?: throw WolinException("Expected '<IRI>' after 'BASE'")
            currentBase = resolveIri(iriTok.raw, currentBase)
        }

        private fun parseTriplesStatement() {
            if (peek() == Token.LBracket) {
                val bnodeSubject = parseBlankNodePropertyList()
                if (peek() != Token.Dot) {
                    parsePredicateObjectList(bnodeSubject)
                }
            } else {
                val subject = parseSubject()
                parsePredicateObjectList(subject)
            }
        }

        private fun parseSubject(): String =
            when (val tok = peek()) {
                is Token.IriRef -> {
                    idx++
                    resolveIri(tok.raw, currentBase)
                }
                is Token.PName -> {
                    idx++
                    expandPName(tok)
                }
                is Token.BlankNodeLabel -> {
                    idx++
                    "_:${tok.label}"
                }
                Token.LParen -> {
                    when (val head = parseCollection()) {
                        is RdfTerm.Iri -> head.value
                        is RdfTerm.BlankNode -> head.id
                        is RdfTerm.Literal -> throw WolinException("Literal cannot be a subject")
                    }
                }
                else -> throw WolinException("Invalid Turtle subject token: $tok")
            }

        private fun parsePredicateObjectList(subject: String) {
            val firstVerb = parseVerb()
            parseObjectList(subject, firstVerb)
            while (peek() == Token.Semicolon) {
                idx++ // consume ';'
                while (peek() == Token.Semicolon) {
                    idx++
                }
                val next = peek()
                if (next == null || next == Token.Dot || next == Token.RBracket) {
                    break
                }
                val verb = parseVerb()
                parseObjectList(subject, verb)
            }
        }

        private fun parseVerb(): String =
            when (val tok = nextToken()) {
                Token.KeywordA -> RDF_TYPE
                is Token.IriRef -> resolveIri(tok.raw, currentBase)
                is Token.PName -> expandPName(tok)
                else -> throw WolinException("Invalid Turtle predicate token: $tok")
            }

        private fun parseObjectList(subject: String, predicate: String) {
            val firstObj = parseObject()
            triples.add(RdfTriple(subject, predicate, firstObj))
            while (peek() == Token.Comma) {
                idx++ // consume ','
                val nextObj = parseObject()
                triples.add(RdfTriple(subject, predicate, nextObj))
            }
        }

        private fun parseObject(): RdfTerm =
            when (val tok = peek()) {
                is Token.IriRef -> {
                    idx++
                    RdfTerm.Iri(resolveIri(tok.raw, currentBase))
                }
                is Token.PName -> {
                    idx++
                    RdfTerm.Iri(expandPName(tok))
                }
                is Token.BlankNodeLabel -> {
                    idx++
                    RdfTerm.BlankNode("_:${tok.label}")
                }
                Token.LBracket -> RdfTerm.BlankNode(parseBlankNodePropertyList())
                Token.LParen -> parseCollection()
                is Token.StringLit -> {
                    idx++
                    val dt = when (val dtTok = tok.datatypeToken) {
                        null -> if (tok.language != null) LANG_STRING else XSD_STRING
                        is Token.IriRef -> resolveIri(dtTok.raw, currentBase)
                        is Token.PName -> expandPName(dtTok)
                        else -> XSD_STRING
                    }
                    RdfTerm.Literal(tok.value, datatype = dt, language = tok.language)
                }
                is Token.PlainLit -> {
                    idx++
                    RdfTerm.Literal(tok.lexical, datatype = tok.datatypeIri)
                }
                else -> throw WolinException("Invalid Turtle object token: $tok")
            }

        private fun parseBlankNodePropertyList(): String {
            if (nextToken() != Token.LBracket) {
                throw WolinException("Expected '[' starting blank node property list")
            }
            val bnodeId = freshBlankNode()
            if (peek() != Token.RBracket) {
                parsePredicateObjectList(bnodeId)
            }
            if (nextToken() != Token.RBracket) {
                throw WolinException("Expected ']' closing blank node property list")
            }
            return bnodeId
        }

        private fun parseCollection(): RdfTerm {
            if (nextToken() != Token.LParen) {
                throw WolinException("Expected '(' starting RDF collection")
            }
            if (peek() == Token.RParen) {
                idx++
                return RdfTerm.Iri(RDF_NIL)
            }
            val headId = freshBlankNode()
            var currentNode = headId
            while (true) {
                val item = parseObject()
                triples.add(RdfTriple(currentNode, RDF_FIRST, item))
                if (peek() == Token.RParen) {
                    idx++
                    triples.add(RdfTriple(currentNode, RDF_REST, RdfTerm.Iri(RDF_NIL)))
                    break
                }
                if (peek() == null) {
                    throw WolinException("Unterminated '(' RDF collection in Turtle document")
                }
                val nextNode = freshBlankNode()
                triples.add(RdfTriple(currentNode, RDF_REST, RdfTerm.BlankNode(nextNode)))
                currentNode = nextNode
            }
            return RdfTerm.BlankNode(headId)
        }

        private fun expandPName(pname: Token.PName): String {
            val ns = prefixes[pname.prefix]
                ?: throw WolinException("Undefined Turtle prefix '${pname.prefix}:'")
            return "$ns${pname.local}"
        }

        private fun expectDot() {
            val tok = nextToken()
            if (tok != Token.Dot) {
                throw WolinException("Expected '.' terminating Turtle statement, got $tok")
            }
        }

        private fun freshBlankNode(): String = "_:b${bnodeCounter++}"

        private fun peek(): Token? = if (idx < tokens.size) tokens[idx] else null

        private fun nextToken(): Token {
            if (idx >= tokens.size) {
                throw WolinException("Unexpected end of Turtle document")
            }
            return tokens[idx++]
        }
    }
}
