"""analyzers/php_flow.py — bounded flow of PHP request input into SQL and shell calls.

`source_auth_scanner` runs this module for the catalog rows marked `flow: php-sql`
(INJ-PHP-001) and `flow: php-shell` (INJ-PHP-002). A hit needs three things in one
function body or script file: a read of request input, its way through assignments,
concatenation, interpolation, `sprintf` and calls, and a SQL or shell call that
receives it in the argument that holds the query or command.

Each value remembers how it was treated and whether it sits inside a quoted literal:
`mysqli_real_escape_string` protects only inside quotes, `escapeshellarg` only for the
shell, numeric casts and numeric validation everywhere. Conditions such as
`is_numeric($id)`, `in_array($x, $allowed)` or an anchored `preg_match` clean the value
inside the guarded branch, and after an `if (!…) { exit; }`. Branches are merged, so a
value tainted on any path stays tainted.

Request input is `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES`, client-controlled
`$_SERVER` fields, `php://input`, request headers, `filter_input`, and the Laravel and
Symfony request objects (`$request`, `request()`, `Request::`). Not followed: calls into
other functions or methods, object properties set elsewhere, includes, session data, and
stored records. Those flows remain for the model review.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

SQL = "sql"
SHELL = "shell"

# ---------------------------------------------------------------------------
# Tokens
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Tok:
    kind: str  # var | name | str | shell | num | op | cast
    text: str
    line: int
    parts: tuple = ()  # str/shell: ("text", str) or ("expr", tuple[Tok, ...])


_OPS = sorted(
    "<<= >>= **= ... <=> === !== ??= ?-> -> => :: == != <> <= >= && || ?? ++ -- += -= *= /= .= %= &= |= ^= << >> ** #[".split(),
    key=len,
    reverse=True,
)
_OP_RE = re.compile("|".join(re.escape(o) for o in _OPS) + r"|[\s\S]")
_SPACE = re.compile(r"[ \t\r\n\f\v]+")
_CAST = re.compile(r"\(\s*(int|integer|float|double|real|bool|boolean|string|binary|array|object|unset)\s*\)", re.I)
_IDENT = re.compile(r"\\?[A-Za-z_\x80-\uffff][\w\x80-\uffff]*(?:\\[A-Za-z_\x80-\uffff][\w\x80-\uffff]*)*")
_VARNAME = re.compile(r"[A-Za-z_\x80-\uffff][\w\x80-\uffff]*")
_NUM = re.compile(r"0[xX][0-9a-fA-F_]+|0[bB][01_]+|\d[\d_]*(?:\.\d+)?(?:[eE][+-]?\d+)?|\.\d+")
_OPEN_TAG = re.compile(r"<\?(?:php\b|=|(?=\s))", re.I)
_HEREDOC = re.compile(r"<<<[ \t]*(['\"]?)([A-Za-z_]\w*)\1\r?\n")
_ESCAPES = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "v": "\v",
    "f": "\f",
    "e": "\x1b",
    "\\": "\\",
    "$": "$",
    '"': '"',
    "`": "`",
}


def lex(text: str) -> list[Tok]:
    """Tokens of the PHP code in `text`; inline HTML is skipped, `?>` ends a statement."""
    out: list[Tok] = []
    pos, line = 0, 1
    while True:
        m = _OPEN_TAG.search(text, pos)
        if not m:
            return out
        line += text.count("\n", pos, m.start())
        if m.group(0) == "<?=":
            out.append(Tok("name", "echo", line))
        pos, line = _lex_php(text, m.end(), line, out, True)


def _lex_php(text: str, pos: int, line: int, out: list[Tok], stop_at_close: bool) -> tuple[int, int]:
    n = len(text)
    while pos < n:
        ch = text[pos]
        if ch in " \t\r\n\f\v":
            end = _SPACE.match(text, pos).end()
            line += text.count("\n", pos, end)
            pos = end
        elif ch == "$" and (m := _VARNAME.match(text, pos + 1)):
            out.append(Tok("var", m.group(0), line))
            pos = m.end()
        elif (ch.isalpha() or ch == "_" or ch == "\\") and (m := _IDENT.match(text, pos)):
            out.append(Tok("name", m.group(0).lstrip("\\"), line))
            pos = m.end()
        elif stop_at_close and text.startswith("?>", pos):
            out.append(Tok("op", ";", line))
            return pos + 2, line
        elif (ch == "#" and not text.startswith("#[", pos)) or text.startswith("//", pos):
            end = text.find("\n", pos)
            end = n if end < 0 else end
            if stop_at_close:
                close = text.find("?>", pos, end)
                end = close if close >= 0 else end
            pos = end
        elif text.startswith("/*", pos):
            end = text.find("*/", pos + 2)
            end = n if end < 0 else end + 2
            line += text.count("\n", pos, end)
            pos = end
        elif ch == "'":
            end, body = _single_quoted(text, pos)
            out.append(Tok("str", body, line, (("text", body),)))
            line += text.count("\n", pos, end)
            pos = end
        elif ch in '"`':
            end = _quoted_end(text, pos, ch)
            parts = _interpolate(text[pos + 1 : max(pos + 1, end - 1)], line)
            out.append(Tok("shell" if ch == "`" else "str", "", line, parts))
            line += text.count("\n", pos, end)
            pos = end
        elif text.startswith("<<<", pos) and (m := _HEREDOC.match(text, pos)):
            closing = re.compile(r"^[ \t]*" + re.escape(m.group(2)) + r"\b", re.M).search(text, m.end())
            body_end = closing.start() if closing else n
            body = text[m.end() : body_end].rstrip("\r\n")
            parts = (("text", body),) if m.group(1) == "'" else _interpolate(body, line + 1)
            out.append(Tok("str", "", line, parts))
            end = closing.end() if closing else n
            line += text.count("\n", pos, end)
            pos = end
        elif ch == "(" and (m := _CAST.match(text, pos)):
            out.append(Tok("cast", m.group(1).lower(), line))
            pos = m.end()
        elif (ch.isdigit() or (ch == "." and text[pos + 1 : pos + 2].isdigit())) and (m := _NUM.match(text, pos)):
            out.append(Tok("num", m.group(0), line))
            pos = m.end()
        elif m := _IDENT.match(text, pos):
            out.append(Tok("name", m.group(0).lstrip("\\"), line))
            pos = m.end()
        else:
            op = _OP_RE.match(text, pos).group(0)
            out.append(Tok("op", op, line))
            pos += len(op)
    return pos, line


def _single_quoted(text: str, pos: int) -> tuple[int, str]:
    out, i, n = [], pos + 1, len(text)
    while i < n:
        ch = text[i]
        if ch == "\\" and i + 1 < n and text[i + 1] in "\\'":
            out.append(text[i + 1])
            i += 2
        elif ch == "'":
            return i + 1, "".join(out)
        else:
            out.append(ch)
            i += 1
    return n, "".join(out)


def _brace_end(text: str, pos: int) -> int:
    """Offset just after the `}` closing the `{` at `pos`, skipping quoted text inside."""
    depth, i, n = 0, pos, len(text)
    while i < n:
        ch = text[i]
        if ch in "'\"":
            j = i + 1
            while j < n and text[j] != ch:
                j += 2 if text[j] == "\\" else 1
            i = j + 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def _quoted_end(text: str, pos: int, quote: str) -> int:
    i, n = pos + 1, len(text)
    while i < n:
        ch = text[i]
        if ch == "\\":
            i += 2
        elif ch == "{" and text.startswith("{$", i):
            i = _brace_end(text, i)
        elif ch == quote:
            return i + 1
        else:
            i += 1
    return n


def _interpolate(body: str, line: int) -> tuple:
    """Literal text and embedded expressions of a double-quoted, backtick or heredoc body."""
    parts: list[tuple] = []
    buf: list[str] = []
    i, n = 0, len(body)

    def flush() -> None:
        if buf:
            parts.append(("text", "".join(buf)))
            buf.clear()

    while i < n:
        ch = body[i]
        if ch == "\\" and i + 1 < n:
            buf.append(_ESCAPES.get(body[i + 1], "\\" + body[i + 1]))
            i += 2
        elif body.startswith("{$", i):
            end = _brace_end(body, i)
            sub: list[Tok] = []
            _lex_php(body[i + 1 : end - 1], 0, line + body.count("\n", 0, i), sub, False)
            flush()
            parts.append(("expr", tuple(sub)))
            i = end
        elif body.startswith("${", i):
            end = body.find("}", i)
            end = n if end < 0 else end
            m = _VARNAME.match(body, i + 2)
            if m:
                flush()
                parts.append(("expr", (Tok("var", m.group(0), line + body.count("\n", 0, i)),)))
            i = end + 1
        elif ch == "$" and (m := _VARNAME.match(body, i + 1)):
            flush()
            parts.append(("expr", (Tok("var", m.group(0), line + body.count("\n", 0, i)),)))
            i = m.end()
            if body.startswith("[", i):
                close = body.find("]", i)
                i = n if close < 0 else close + 1
            elif body.startswith("->", i) and (p := _VARNAME.match(body, i + 2)):
                i = p.end()
        else:
            buf.append(ch)
            i += 1
    flush()
    return tuple(parts)


# ---------------------------------------------------------------------------
# Values
# ---------------------------------------------------------------------------
# A value is a frozenset of Occ: one request-input read it contains, how that read was
# treated (state), and the quote it sits in once it was placed into a literal (ctx).


@dataclass(frozen=True, order=True)
class Occ:
    src_line: int
    state: str  # raw | escaped | sqlquoted | noquote | nosquote | shellarg
    ctx: str | None = None  # None (not yet in a literal), "'" or '"'


EMPTY: frozenset = frozenset()
_MAX_OCCS = 8


def _cap(value: frozenset) -> frozenset:
    return value if len(value) <= _MAX_OCCS else frozenset(sorted(value)[:_MAX_OCCS])


def _source(line: int) -> frozenset:
    return frozenset({Occ(line, "raw")})


def _with_state(value: frozenset, state: str) -> frozenset:
    return frozenset(Occ(o.src_line, state, o.ctx) for o in value)


def _in_quote(value: frozenset, quote: str | None) -> frozenset:
    if quote is None:
        return value
    return frozenset(o if o.ctx else Occ(o.src_line, o.state, quote) for o in value)


def dangerous(occ: Occ, sink: str) -> bool:
    """Whether a value treated as `occ.state` and placed in `occ.ctx` can still change the query or command."""
    state, ctx = occ.state, occ.ctx
    if sink == SQL:
        if state == "sqlquoted":
            return False
        if state in ("escaped", "noquote"):
            return ctx is None
        if state == "nosquote":
            return ctx != "'"
        return True
    if state == "shellarg":
        return False
    if state in ("noquote", "nosquote"):
        return ctx != "'"  # inside '…' the shell interprets nothing but the closing quote
    return True


# ---------------------------------------------------------------------------
# Catalogs
# ---------------------------------------------------------------------------

_SUPERGLOBALS = {
    "_GET",
    "_POST",
    "_REQUEST",
    "_COOKIE",
    "_FILES",
    "HTTP_GET_VARS",
    "HTTP_POST_VARS",
    "HTTP_COOKIE_VARS",
    "HTTP_POST_FILES",
    "HTTP_RAW_POST_DATA",
}
# $_SERVER fields the client sets; HTTP_* request headers are added by prefix.
_SERVER_KEYS = {
    "REQUEST_URI",
    "QUERY_STRING",
    "PHP_SELF",
    "PATH_INFO",
    "ORIG_PATH_INFO",
    "PATH_TRANSLATED",
    "REDIRECT_URL",
    "REDIRECT_QUERY_STRING",
}
# $_FILES fields the server fills in.
_SERVER_SET_FILE_KEYS = {"tmp_name", "size", "error"}
_REQUEST_VARS = {"request", "req"}
# Request-object methods that return no client text: identity, flags, counts, typed values.
_REQUEST_CLEAN = {
    "user",
    "session",
    "ip",
    "ips",
    "getclientip",
    "method",
    "getmethod",
    "ismethod",
    "ismethodsafe",
    "ajax",
    "isxmlhttprequest",
    "pjax",
    "prefetch",
    "secure",
    "issecure",
    "wantsjson",
    "expectsjson",
    "acceptsjson",
    "accepts",
    "isjson",
    "has",
    "hasany",
    "filled",
    "isnotfilled",
    "anyfilled",
    "missing",
    "exists",
    "boolean",
    "integer",
    "float",
    "date",
    "enum",
    "hasfile",
    "hassession",
    "hasheader",
    "hascookie",
    "routeis",
    "is",
    "fullurlis",
    "getport",
    "getscheme",
    "getlocale",
}
_REQUEST_FACADES = {"request", "input"}
_FACADE_SOURCE_METHODS = {
    "input",
    "get",
    "query",
    "post",
    "all",
    "only",
    "except",
    "cookie",
    "header",
    "json",
    "route",
    "file",
    "old",
    "string",
    "str",
    "getcontent",
}

# function -> index of the argument holding the SQL text; -1 = last, -2 = second to last.
_SQL_FUNCS = {
    "mysql_query": 0,
    "mysql_unbuffered_query": 0,
    "mysql_db_query": 1,
    "mysqli_query": 1,
    "mysqli_real_query": 1,
    "mysqli_multi_query": 1,
    "mysqli_prepare": 1,
    "mysqli_execute_query": 1,
    "mssql_query": 0,
    "pg_query": -1,
    "pg_send_query": 1,
    "pg_prepare": -1,
    "pg_query_params": -2,
    "sqlsrv_query": 1,
    "sqlsrv_prepare": 1,
    "oci_parse": 1,
    "odbc_exec": 1,
    "odbc_prepare": 1,
    "db2_exec": 1,
    "db2_prepare": 1,
}
_SQL_METHODS = {
    "query",
    "exec",
    "prepare",
    "multi_query",
    "real_query",
    "execute_query",
    "createquery",
    "createnativequery",
    "executequery",
    "executestatement",
    "executeupdate",
    "fetchallassociative",
    "fetchassociative",
    "fetchone",
    "fetchallnumeric",
    "fetchnumeric",
    "fetchfirstcolumn",
    "fetchallkeyvalue",
    "whereraw",
    "orwhereraw",
    "havingraw",
    "orhavingraw",
    "orderbyraw",
    "selectraw",
    "groupbyraw",
    "fromraw",
}
# Query-builder methods taking raw SQL, also called statically on Eloquent models.
_RAW_BUILDER_METHODS = {
    "whereraw",
    "orwhereraw",
    "havingraw",
    "orhavingraw",
    "orderbyraw",
    "selectraw",
    "groupbyraw",
    "fromraw",
}
_SQL_STATIC = {
    "db": {"select", "selectone", "insert", "update", "delete", "statement", "unprepared", "raw", "cursor", "scalar"},
}
_SHELL_FUNCS = {"system", "exec", "shell_exec", "passthru", "popen", "proc_open", "pcntl_exec", "expect_popen"}
_SHELL_STATIC = {"process": {"fromshellcommandline", "run", "start"}}

# function -> (argument index, resulting state)
_ESCAPERS = {
    "mysql_real_escape_string": (0, "escaped"),
    "mysql_escape_string": (0, "escaped"),
    "mysqli_real_escape_string": (1, "escaped"),
    "mysqli_escape_string": (1, "escaped"),
    "addslashes": (0, "escaped"),
    "sqlite_escape_string": (0, "escaped"),
    "pg_escape_string": (-1, "escaped"),
    "pg_escape_literal": (-1, "sqlquoted"),
    "pg_escape_identifier": (-1, "sqlquoted"),
    "escapeshellarg": (0, "shellarg"),
}
_ESCAPER_METHODS = {
    "real_escape_string": "escaped",
    "escape_string": "escaped",
    "escapestring": "escaped",
    "escape_str": "escaped",
    "quote": "sqlquoted",
    "escape": "sqlquoted",
}
# Functions that return a number, a flag, a hash or an encoding without quotes.
_CLEAN_FUNCS = {
    "intval",
    "floatval",
    "doubleval",
    "boolval",
    "abs",
    "round",
    "floor",
    "ceil",
    "count",
    "sizeof",
    "strlen",
    "mb_strlen",
    "strcmp",
    "strcasecmp",
    "strncmp",
    "strncasecmp",
    "strpos",
    "stripos",
    "strrpos",
    "mb_strpos",
    "substr_count",
    "isset",
    "empty",
    "in_array",
    "array_key_exists",
    "preg_match",
    "preg_match_all",
    "md5",
    "sha1",
    "crc32",
    "hash",
    "hash_hmac",
    "password_hash",
    "password_verify",
    "bin2hex",
    "dechex",
    "hexdec",
    "octdec",
    "bindec",
    "decbin",
    "number_format",
    "urlencode",
    "rawurlencode",
    "base64_encode",
    "uniqid",
    "time",
    "microtime",
    "date",
    "gmdate",
    "mktime",
    "strtotime",
    "checkdate",
    "rand",
    "mt_rand",
    "random_int",
    "printf",
    "vprintf",
    "print_r",
    "var_dump",
}
_CLEAN_PREFIXES = ("is_", "ctype_")
# Functions that undo escaping or decode text: their result is raw again.
_DECODERS = {
    "stripslashes",
    "stripcslashes",
    "html_entity_decode",
    "htmlspecialchars_decode",
    "urldecode",
    "rawurldecode",
    "base64_decode",
    "hex2bin",
    "quoted_printable_decode",
    "convert_uudecode",
    "json_decode",
    "unserialize",
}
_VALIDATORS = {
    "is_numeric",
    "is_int",
    "is_integer",
    "is_long",
    "is_float",
    "is_double",
    "is_bool",
    "ctype_digit",
    "ctype_alnum",
    "ctype_alpha",
    "ctype_xdigit",
    "ctype_lower",
    "ctype_upper",
    "in_array",
    "array_key_exists",
}
_SAFE_FILTERS = {
    "FILTER_VALIDATE_INT",
    "FILTER_VALIDATE_FLOAT",
    "FILTER_VALIDATE_BOOL",
    "FILTER_VALIDATE_BOOLEAN",
    "FILTER_VALIDATE_IP",
    "FILTER_VALIDATE_MAC",
    "FILTER_SANITIZE_NUMBER_INT",
    "FILTER_SANITIZE_NUMBER_FLOAT",
}
_FILTER_STATES = {
    "FILTER_SANITIZE_SPECIAL_CHARS": "noquote",
    "FILTER_SANITIZE_FULL_SPECIAL_CHARS": "noquote",
    "FILTER_SANITIZE_ADD_SLASHES": "escaped",
    "FILTER_SANITIZE_MAGIC_QUOTES": "escaped",
}
# Calls that end the request like `exit`: WordPress, Laravel.
_TERMINATING_FUNCS = {"wp_die", "abort", "dd"}
_SCALAR_CASTS = {"int", "integer", "float", "double", "real", "bool", "boolean", "unset"}
_SETTYPE_SCALARS = {"int", "integer", "float", "double", "bool", "boolean"}
_ASSIGN_OPS = {"=", ".=", "+=", "-=", "*=", "/=", "%=", "**=", "??=", "&=", "|=", "^=", "<<=", ">>="}
_NUMERIC_ASSIGN = _ASSIGN_OPS - {"=", ".=", "??="}
_COMPARE_OPS = {"==", "!=", "===", "!==", "<", ">", "<=", ">=", "<>", "<=>"}
_ARITH_OPS = {"+", "-", "*", "/", "%", "**", "<<", ">>", "&", "|", "^"}
_OPENERS = {"(": ")", "[": "]", "{": "}", "#[": "]"}
_CLASS_WORDS = {"class", "interface", "trait", "enum"}
_MODIFIERS = {"abstract", "final", "readonly"}
_REGEX_SAFE_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.@+:/,=-")


def _restrictive_regex(pattern: str) -> bool:
    """An anchored PCRE pattern whose matches contain only letters, digits and `_.@+:/,=-`."""
    if len(pattern) < 2 or pattern[0].isalnum() or pattern[0] == "\\":
        return False
    close = {"(": ")", "{": "}", "[": "]", "<": ">"}.get(pattern[0], pattern[0])
    end = pattern.rfind(close)
    if end <= 0 or "m" in pattern[end + 1 :]:
        return False
    body = pattern[1:end]
    if body.startswith("^"):
        body = body[1:]
    elif body.startswith("\\A"):
        body = body[2:]
    else:
        return False
    for tail in ("\\z", "\\Z", "$"):
        if body.endswith(tail) and not body.endswith("\\" + tail):
            body = body[: -len(tail)]
            break
    else:
        return False
    i, n = 0, len(body)
    while i < n:
        ch = body[i]
        if ch == "\\":
            nxt = body[i + 1 : i + 2]
            if not (nxt in ("d", "w") or (nxt and nxt in _REGEX_SAFE_CHARS and not nxt.isalnum())):
                return False
            i += 2
        elif ch == "[":
            j = i + 1
            if body[j : j + 1] == "^":
                return False
            while j < n and body[j] != "]":
                if body[j] == "\\":
                    if body[j + 1 : j + 2] not in ("d", "w", ".", "-", "_", "@", "+", "/", ":"):
                        return False
                    j += 2
                    continue
                if body[j] not in _REGEX_SAFE_CHARS:
                    return False
                j += 1
            if j >= n:
                return False
            i = j + 1
        elif ch in "()|*+?":
            i += 1
        elif ch == "{":
            j = body.find("}", i)
            if j < 0 or not re.fullmatch(r"\{\d*(,\d*)?\}", body[i : j + 1]):
                return False
            i = j + 1
        elif ch in _REGEX_SAFE_CHARS and ch != ".":
            i += 1
        else:
            return False
    return True


def _forbidden_char_regex(pattern: str) -> bool:
    """`/[^a-z0-9_]/i`: a match means a character outside a safe set, so no match leaves only safe ones."""
    if len(pattern) < 2 or pattern[0].isalnum() or pattern[0] == "\\":
        return False
    end = pattern.rfind({"(": ")", "{": "}", "[": "]", "<": ">"}.get(pattern[0], pattern[0]))
    if end <= 0 or "m" in pattern[end + 1 :] or not re.fullmatch(r"[a-zA-Z]*", pattern[end + 1 :]):
        return False
    m = re.fullmatch(r"\[\^((?:[a-zA-Z0-9]-[a-zA-Z0-9]|\\[dw.\-_@+/:]|[a-zA-Z0-9_.@+:/,=-])+)\]\+?", pattern[1:end])
    return bool(m)


def _removal_state(pattern: str) -> str | None:
    """State of a value after `preg_replace(pattern, '', …)`, or None when it changes nothing that matters."""
    if len(pattern) < 2 or pattern[0].isalnum() or pattern[0] == "\\":
        return None
    end = pattern.rfind({"(": ")", "{": "}", "[": "]", "<": ">"}.get(pattern[0], pattern[0]))
    if end <= 0 or not pattern[end + 1 :].isalpha() and pattern[end + 1 :]:
        return None
    body = pattern[1:end]
    if body in ("\\W", "[^\\w]", "\\W+", "[^\\w]+") or re.fullmatch(r"\[\^(?:a-z|A-Z|0-9|\\d|\\w|_)+\]\+?", body):
        return "clean"
    if re.fullmatch(r"\[\^[^\]]*\]\+?", body) and not re.search(r"['\"\\]", body[2:]):
        return "noquote"
    removed_single = "'" in body or "\\x27" in body
    removed_double = '"' in body or "\\x22" in body
    if body.startswith("[^"):
        return None
    if removed_single and removed_double:
        return "noquote"
    if removed_single:
        return "nosquote"
    return None


# ---------------------------------------------------------------------------
# Analysis
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Hit:
    sink: str  # SQL | SHELL
    line: int
    src_line: int


# Every source above is spelled with one of these; a file without them cannot have a hit.
_SOURCE_HINT = re.compile(
    r"\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\b|\$HTTP_\w+|php://input|getallheaders|apache_request_headers"
    r"|filter_input|\$req(?:uest)?\b|\brequest\s*\(|\b(?:Request|Input)\s*::",
    re.I,
)


def scan(text: str) -> list[Hit]:
    """SQL and shell calls in one PHP file that receive request input in their query or command."""
    if not _SOURCE_HINT.search(text):
        return []
    toks = lex(text)
    analyzer = _Analyzer(toks)
    try:
        analyzer.block(0, len(toks), {})
    except RecursionError:
        pass  # code nested beyond Python's stack: keep the hits found before it
    return sorted(analyzer.hits.values(), key=lambda h: (h.line, h.sink))


# A variable missing from a state holds no request input. A request field such as
# `$_GET[id]` is the opposite: missing means unchecked input, and an entry records a
# check or a new value, which counts after a merge only if every path has it.


def _merge(*states):
    live = [s for s in states if s is not None]
    if not live:
        return None
    out = dict(live[0])
    for state in live[1:]:
        for name, value in state.items():
            out[name] = _cap(out.get(name, EMPTY) | value)
    for name in [n for n in out if n.startswith("$") and any(n not in s for s in live)]:
        del out[name]
    return out


def _cleaned(state, names):
    if state is None:
        return None
    out = dict(state)
    for name in names:
        if name.startswith("$"):
            out[name] = EMPTY
        else:
            out.pop(name, None)
    return out


class _Analyzer:
    def __init__(self, toks: list[Tok]) -> None:
        self.t = toks
        self.m = self._pairs()
        self.hits: dict[tuple[str, int], Hit] = {}
        self.consts: dict[str, str] = {}
        self.jumps: list[list] = []

    # --- token helpers ------------------------------------------------------

    def _pairs(self) -> dict[int, int]:
        pairs, stack = {}, []
        for i, tok in enumerate(self.t):
            if tok.kind != "op":
                continue
            if tok.text in _OPENERS:
                stack.append(i)
            elif tok.text in (")", "]", "}"):
                while stack and _OPENERS[self.t[stack[-1]].text] != tok.text:
                    stack.pop()
                if stack:
                    pairs[stack.pop()] = i
        return pairs

    def _is(self, i: int, kind: str, text: str | None = None) -> bool:
        if i >= len(self.t):
            return False
        tok = self.t[i]
        return tok.kind == kind and (text is None or tok.text == text)

    def _op(self, i: int, *texts: str) -> bool:
        return i < len(self.t) and self.t[i].kind == "op" and self.t[i].text in texts

    def _word(self, i: int, *words: str) -> bool:
        return i < len(self.t) and self.t[i].kind == "name" and self.t[i].text.lower() in words

    def _close(self, i: int, limit: int) -> int:
        return min(self.m.get(i, limit - 1), limit - 1)

    def _top(self, lo: int, hi: int):
        """Indices of the depth-0 tokens in [lo, hi)."""
        i = lo
        while i < hi:
            yield i
            if self.t[i].kind == "op" and self.t[i].text in _OPENERS and i in self.m:
                i = self.m[i] + 1
            else:
                i += 1

    def _split(self, lo: int, hi: int, ops: set[str], words: set[str] = frozenset()) -> list[tuple[int, int]]:
        parts, start = [], lo
        for i in self._top(lo, hi):
            tok = self.t[i]
            if (tok.kind == "op" and tok.text in ops) or (tok.kind == "name" and tok.text.lower() in words):
                parts.append((start, i))
                start = i + 1
        parts.append((start, hi))
        return parts

    def _stmt_end(self, i: int, end: int) -> int:
        for j in self._top(i, end):
            if self._op(j, ";"):
                return j
        return end

    def _strip(self, lo: int, hi: int) -> tuple[int, int]:
        while lo < hi and self._op(lo, "(") and self.m.get(lo) == hi - 1:
            lo, hi = lo + 1, hi - 1
        return lo, hi

    def _args(self, lp: int, rp: int) -> list[tuple[int, int]]:
        if rp <= lp + 1:
            return []
        args = []
        for lo, hi in self._split(lp + 1, rp, {","}):
            if lo < hi and self._is(lo, "name") and self._op(lo + 1, ":") and not self._op(lo + 1, "::"):
                lo += 2  # named argument
            if lo < hi and self._op(lo, "..."):
                lo += 1
            if lo < hi:
                args.append((lo, hi))
        return args

    def _hit(self, sink: str, value: frozenset, line: int) -> None:
        bad = [o for o in value if dangerous(o, sink)]
        if bad and (sink, line) not in self.hits:
            self.hits[(sink, line)] = Hit(sink, line, min(o.src_line for o in bad))

    # --- statements ---------------------------------------------------------

    def block(self, i: int, end: int, state, stop: tuple[str, ...] = ()):
        """Run the statements in [i, end); return the state after them (None: no path continues)."""
        dead = state is None
        state = {} if dead else state
        while i < end:
            if stop and self._word(i, *stop):
                break
            i, state = self.stmt(i, end, state)
            if state is None:
                dead, state = True, {}
        return (None if dead else state) if not stop else (i, None if dead else state)

    def stmt(self, i: int, end: int, st):
        tok = self.t[i]
        if tok.kind == "op":
            if tok.text == "{" and i in self.m:
                j = self._close(i, end)
                return j + 1, self.block(i + 1, j, st)
            if tok.text == "#[":
                return self._close(i, end) + 1, st
            if tok.text in (";", "}", ")", "]"):
                return i + 1, st
        if tok.kind == "name":
            word = tok.text.lower()
            if word in ("if", "elseif"):
                return self._if(i, end, st)
            if word in ("while", "for", "foreach", "switch"):
                return self._loop(i, end, st, word)
            if word == "do":
                return self._do(i, end, st)
            if word == "try":
                return self._try(i, end, st)
            if word == "function" and self._is(i + 1, "name") or (word == "function" and self._op(i + 1, "&")):
                return self._function(i, end), st
            if word in _CLASS_WORDS or (word in _MODIFIERS and self._word(i + 1, *_CLASS_WORDS, *_MODIFIERS)):
                return self._class(i, end), st
            if word in ("return", "throw", "exit", "die"):
                j = self._stmt_end(i, end)
                self.eval(i + 1, j, st)
                return j + 1, None
            if word in ("break", "continue"):
                if self.jumps:
                    self.jumps[-1].append(st)
                return self._stmt_end(i, end) + 1, None
            if word in ("global", "use", "goto", "const", "declare", "namespace", "case", "default"):
                if word == "namespace" or word == "declare":
                    for j in self._top(i, end):
                        if self._op(j, ";"):
                            return j + 1, st
                        if self._op(j, "{"):
                            k = self._close(j, end)
                            return k + 1, self.block(j + 1, k, st)
                    return end, st
                if word in ("case", "default"):
                    return self._case_label_end(i, end), st
                return self._stmt_end(i, end) + 1, st
            if word in ("else", "endif", "endwhile", "endfor", "endforeach", "endswitch", "enddeclare"):
                return i + 1, st
            if word in ("echo", "print", "include", "include_once", "require", "require_once") or (
                word == "static" and self._is(i + 1, "var")
            ):
                j = self._stmt_end(i, end)
                for lo, hi in self._split(i + 1, j, {","}):
                    self.eval(lo, hi, st)
                return j + 1, st
            if word == "unset" and self._op(i + 1, "("):
                rp = self._close(i + 1, end)
                for lo, _hi in self._args(i + 1, rp):
                    if self._is(lo, "var"):
                        st.pop(self.t[lo].text, None)
                return self._stmt_end(rp, end) + 1, st
        j = self._stmt_end(i, end)
        self.eval(i, j, st)
        if tok.kind == "name" and tok.text.lower() in _TERMINATING_FUNCS and self._op(i + 1, "("):
            return j + 1, None
        return j + 1, st

    def _case_label_end(self, i: int, end: int) -> int:
        for j in self._top(i, end):
            if self._op(j, ":", ";"):
                return j + 1
        return end

    def _body(self, k: int, end: int, st, closers: tuple[str, ...]):
        """A control body: one statement, a braced block, or `: … endX;` alternative syntax."""
        if self._op(k, ":"):
            k, st = self.block(k + 1, end, st, stop=closers)
            return k, st
        return self.stmt(k, end, st) if k < end else (k, st)

    def _if(self, i: int, end: int, st):
        lp = i + 1
        if not self._op(lp, "("):
            return self._stmt_end(i, end) + 1, st
        rp = self._close(lp, end)
        self.eval(lp + 1, rp, st)
        true_names, false_names = self.facts(lp + 1, rp)
        alt = self._op(rp + 1, ":")
        k, then_state = self._body(rp + 1, end, _cleaned(st, true_names), ("elseif", "else", "endif"))
        else_entry = _cleaned(st, false_names)
        if self._word(k, "elseif") or (self._word(k, "else") and self._word(k + 1, "if")):
            k += 0 if self._word(k, "elseif") else 1
            k, else_state = self._if(k, end, else_entry or {})
            if else_entry is None:
                else_state = None
        elif self._word(k, "else"):
            k, else_state = self._body(k + 1, end, else_entry, ("endif",))
        else:
            else_state = else_entry
        if alt and self._word(k, "endif"):
            k = self._stmt_end(k, end) + 1
        return k, _merge(then_state, else_state)

    def _loop(self, i: int, end: int, st, word: str):
        lp = i + 1
        if not self._op(lp, "("):
            return self._stmt_end(i, end) + 1, st
        rp = self._close(lp, end)
        entry = st
        body_entry = dict(st)
        if word == "foreach":
            parts = self._split(lp + 1, rp, set(), {"as"})
            value = self.eval(*parts[0], st) if parts else EMPTY
            for lo, hi in parts[1:]:
                for j in range(lo, hi):
                    if self._is(j, "var"):
                        body_entry[self.t[j].text] = value
        elif word == "for":
            for lo, hi in self._split(lp + 1, rp, {";"}):
                for clo, chi in self._split(lo, hi, {","}):
                    self.eval(clo, chi, body_entry)
        else:
            self.eval(lp + 1, rp, body_entry)
        if word == "while":
            body_entry = _cleaned(body_entry, self.facts(lp + 1, rp)[0])
        closer = {"while": "endwhile", "for": "endfor", "foreach": "endforeach", "switch": "endswitch"}[word]
        self.jumps.append([])
        if word == "switch":
            k, body_state = self._switch(rp + 1, end, body_entry, closer)
        else:
            k, body_state = self._body(rp + 1, end, body_entry, (closer,))
        jumps = self.jumps.pop()
        if self._word(k, closer):
            k = self._stmt_end(k, end) + 1
        return k, _merge(entry, body_state, *jumps)

    def _switch(self, k: int, end: int, st, closer: str):
        if self._op(k, "{"):
            body_end, after = self._close(k, end), self._close(k, end) + 1
            lo = k + 1
        elif self._op(k, ":"):
            lo = k + 1
            body_end = next((j for j in self._top(lo, end) if self._word(j, closer)), end)
            after = body_end
        else:
            return k, st
        labels = [j for j in self._top(lo, body_end) if self._word(j, "case", "default")]
        ends = [st]
        for n, label in enumerate(labels):
            start = self._case_label_end(label, body_end)
            stop = labels[n + 1] if n + 1 < len(labels) else body_end
            ends.append(self.block(start, stop, dict(st)))
        return after, _merge(*ends)

    def _do(self, i: int, end: int, st):
        k, body_state = self.stmt(i + 1, end, dict(st)) if i + 1 < end else (end, st)
        if self._word(k, "while") and self._op(k + 1, "("):
            rp = self._close(k + 1, end)
            self.eval(k + 2, rp, body_state if body_state is not None else {})
            k = self._stmt_end(rp, end) + 1
        return k, _merge(st, body_state)

    def _try(self, i: int, end: int, st):
        if not self._op(i + 1, "{"):
            return i + 1, st
        rb = self._close(i + 1, end)
        try_state = self.block(i + 2, rb, dict(st))
        k, ends = rb + 1, [try_state]
        catch_entry = _merge(st, try_state)
        while self._word(k, "catch") and self._op(k + 1, "("):
            rp = self._close(k + 1, end)
            if not self._op(rp + 1, "{"):
                break
            cb = self._close(rp + 1, end)
            ends.append(self.block(rp + 2, cb, dict(catch_entry)))
            k = cb + 1
        state = _merge(*ends)
        if self._word(k, "finally") and self._op(k + 1, "{"):
            fb = self._close(k + 1, end)
            state = self.block(k + 2, fb, state if state is not None else {})
            k = fb + 1
        return k, state

    def _function(self, i: int, end: int, inherited=None) -> int:
        """Analyse a function or method body in its own scope; return the index after it."""
        lp = next((j for j in range(i, min(end, i + 6)) if self._op(j, "(")), None)
        if lp is None:
            return self._stmt_end(i, end) + 1
        k = self._close(lp, end) + 1
        while k < end and not self._op(k, "{", ";"):
            if self._op(k, "("):
                k = self._close(k, end)
            k += 1
        if not self._op(k, "{"):
            return k + 1
        rb = self._close(k, end)
        saved_consts, saved_jumps = self.consts, self.jumps
        self.consts, self.jumps = {}, []
        self.block(k + 1, rb, dict(inherited or {}))
        self.consts, self.jumps = saved_consts, saved_jumps
        return rb + 1

    def _class(self, i: int, end: int) -> int:
        k = i
        while k < end and not self._op(k, "{", ";"):
            k += 1
        if not self._op(k, "{"):
            return k + 1
        rb = self._close(k, end)
        self._class_body(k + 1, rb)
        return rb + 1

    def _class_body(self, lo: int, hi: int) -> None:
        j = lo
        while j < hi:
            if self._word(j, "function"):
                j = self._function(j, hi)
            elif self._op(j, "{", "(", "[", "#[") and j in self.m:
                j = self._close(j, hi) + 1
            else:
                j += 1

    # --- conditions ---------------------------------------------------------

    def facts(self, lo: int, hi: int) -> tuple[set[str], set[str]]:
        """Variables a condition validates when it is true and when it is false."""
        lo, hi = self._strip(lo, hi)
        if lo >= hi:
            return set(), set()
        parts = self._split(lo, hi, {"||"}, {"or"})
        if len(parts) > 1:
            return set(), set().union(*(self.facts(a, b)[1] for a, b in parts))
        parts = self._split(lo, hi, {"&&"}, {"and"})
        if len(parts) > 1:
            return set().union(*(self.facts(a, b)[0] for a, b in parts)), set()
        if self._op(lo, "!"):
            true_names, false_names = self.facts(lo + 1, hi)
            return false_names, true_names
        compare = next((j for j in self._top(lo, hi) if self._op(j, *_COMPARE_OPS)), None)
        if compare is not None:
            return self._compare_facts(lo, compare, hi)
        if self._is(lo, "name") and self._op(lo + 1, "(") and self._close(lo + 1, hi) == hi - 1:
            return self._validated(self.t[lo].text.lower(), self._args(lo + 1, hi - 1))
        return set(), set()

    def _literal(self, lo: int, hi: int):
        if hi - lo != 1:
            return None
        tok = self.t[lo]
        if tok.kind == "num":
            return tok.text not in ("0", "0.0")
        if tok.kind == "str" and all(p[0] == "text" for p in tok.parts):
            return "".join(p[1] for p in tok.parts) not in ("", "0")
        if tok.kind == "name" and tok.text.lower() in ("true", "false", "null"):
            return tok.text.lower() == "true"
        return None

    def _compare_facts(self, lo: int, k: int, hi: int) -> tuple[set[str], set[str]]:
        op = self.t[k].text
        left, right = (lo, k), (k + 1, hi)
        truth = self._literal(*right)
        other = left
        if truth is None:
            truth, other = self._literal(*left), right
        if truth is None:
            return set(), set()
        name = self._base_name(*other)
        if name is not None:
            if op in ("==", "==="):
                return {name}, set()
            if op in ("!=", "!==", "<>"):
                return set(), {name}
            return set(), set()
        positive = {
            "==": truth,
            "===": truth,
            "!=": not truth,
            "!==": not truth,
            "<>": not truth,
            ">": True,
            ">=": truth,
        }
        polarity = positive.get(op, False if op == "<" else None)
        if polarity is None:
            return set(), set()
        true_names, false_names = self.facts(*other)
        return (true_names, false_names) if polarity else (false_names, true_names)

    def _base_name(self, lo: int, hi: int) -> str | None:
        lo, hi = self._strip(lo, hi)
        if lo < hi and self._is(lo, "var") and (self.t[lo].text in _SUPERGLOBALS or self.t[lo].text == "_SERVER"):
            field = self._field_key(self.t[lo].text, lo + 1)
            return field if field is not None and lo + 4 == hi else None
        if lo < hi and self._is(lo, "var"):
            j = lo + 1
            while j < hi:
                if self._op(j, "[") and j in self.m:
                    j = self.m[j] + 1
                elif self._op(j, "->", "?->") and self._is(j + 1, "name"):
                    j += 2
                else:
                    return None
            return self.t[lo].text
        return None

    def _validated(self, func: str, args: list[tuple[int, int]]) -> tuple[set[str], set[str]]:
        """Variables a validating call checks when it returns true and when it returns false."""
        func = func.rsplit("\\", 1)[-1]
        target, when_false = None, False
        if func in _VALIDATORS and args:
            target = args[0]
        elif func == "preg_match" and len(args) >= 2 and self._restrictive_arg(*args[0]):
            target = args[1]
        elif func == "preg_match" and len(args) >= 2 and _forbidden_char_regex(self._const_text(*args[0]) or ""):
            target, when_false = args[1], True
        elif func == "filter_var" and len(args) >= 2 and self._filter_name(*args[1]) in _SAFE_FILTERS:
            target = args[0]
        name = self._base_name(*target) if target else None
        names = {name} if name else set()
        return (set(), names) if when_false else (names, set())

    def _restrictive_arg(self, lo: int, hi: int) -> bool:
        text = self._const_text(lo, hi)
        return text is not None and _restrictive_regex(text)

    def _const_text(self, lo: int, hi: int) -> str | None:
        lo, hi = self._strip(lo, hi)
        if hi - lo != 1:
            return None
        tok = self.t[lo]
        if tok.kind == "str" and all(p[0] == "text" for p in tok.parts):
            return "".join(p[1] for p in tok.parts)
        if tok.kind == "var":
            return self.consts.get(tok.text)
        return None

    def _filter_name(self, lo: int, hi: int) -> str | None:
        for j in range(lo, hi):
            if self._is(j, "name") and self.t[j].text.upper().startswith("FILTER_"):
                return self.t[j].text.upper()
        return None

    # --- expressions --------------------------------------------------------

    def eval(self, lo: int, hi: int, st) -> frozenset:
        """Value of the expression in [lo, hi); assignments update `st`, sink calls record hits."""
        if st is None:
            st = {}
        lo, hi = self._strip(lo, hi)
        if lo >= hi:
            return EMPTY
        # One pass collects the depth-0 operators; they are then applied from the lowest precedence up.
        assign, ternary = None, False
        words, logic, compare, dots, arith = [], [], [], [], []
        for j in self._top(lo, hi):
            tok = self.t[j]
            if tok.kind == "op":
                op = tok.text
                if op in _ASSIGN_OPS:
                    if assign is None and j > lo:
                        assign = j
                elif op in ("?", "??"):
                    ternary = True
                elif op in ("||", "&&"):
                    logic.append(j)
                elif op in _COMPARE_OPS:
                    compare.append(j)
                elif op == ".":
                    dots.append(j)
                elif op in _ARITH_OPS and j > lo and self._operand_end(j - 1):
                    arith.append(j)
            elif tok.kind == "name" and tok.text.lower() in ("or", "and", "xor", "instanceof"):
                (compare if tok.text.lower() == "instanceof" else words).append(j)
        if assign is not None:
            return self._assign(lo, assign, hi, st)
        if ternary and not words and (value := self._ternary(lo, hi, st)) is not None:
            return value
        for cut in (words, logic, compare):
            if cut:
                for a, b in _pieces(lo, hi, cut):
                    self.eval(a, b, st)
                return EMPTY
        if dots:
            return self._concat(_pieces(lo, hi, dots), st)
        if arith:
            for a, b in _pieces(lo, hi, arith):
                self.eval(a, b, st)
            return EMPTY
        return self._unary(lo, hi, st)

    def _operand_end(self, j: int) -> bool:
        tok = self.t[j]
        return tok.kind in ("var", "name", "num", "str", "shell") or (tok.kind == "op" and tok.text in (")", "]", "}"))

    def _assign(self, lo: int, k: int, hi: int, st) -> frozenset:
        op = self.t[k].text
        value = self.eval(k + 1, hi, st)
        if op in _NUMERIC_ASSIGN:
            value = EMPTY
        const = self._const_text(k + 1, hi) if op == "=" else None
        if self._is(lo, "var"):
            name = self.t[lo].text
            weak = lo + 1 < k
            if const is not None and not weak:
                self.consts[name] = const
            else:
                self.consts.pop(name, None)
            old = st.get(name, EMPTY)
            if op in (".=", "??=") or (weak and op not in _NUMERIC_ASSIGN):
                new = old | value
            elif op in _NUMERIC_ASSIGN:
                new = old if weak else EMPTY
            else:
                new = value
            if new:
                st[name] = _cap(new)
            else:
                st.pop(name, None)
        elif self._word(lo, "list") or self._op(lo, "["):
            for j in range(lo, k):
                if self._is(j, "var"):
                    if value:
                        st[self.t[j].text] = value
                    else:
                        st.pop(self.t[j].text, None)
        return value

    def _ternary(self, lo: int, hi: int, st):
        depth, question = 0, None
        for j in self._top(lo, hi):
            if self._op(j, "??") and question is None and depth == 0:
                return _cap(self.eval(lo, j, st) | self.eval(j + 1, hi, st))
            if self._op(j, "?"):
                if question is None:
                    question = j
                depth += 1
            elif self._op(j, ":") and question is not None:
                depth -= 1
                if depth == 0:
                    true_names, false_names = self.facts(lo, question)
                    cond = self.eval(lo, question, st)
                    if j == question + 1:  # `?:`
                        return _cap(cond | self.eval(j + 1, hi, st))
                    a = self.eval(question + 1, j, _cleaned(st, true_names))
                    b = self.eval(j + 1, hi, _cleaned(st, false_names))
                    return _cap(a | b)
        return None

    def _concat(self, parts: list[tuple[int, int]], st) -> frozenset:
        """Concatenation: each value takes the quote of the literal text before it."""
        quote: str | None = None
        out = set()
        for lo, hi in parts:
            lo, hi = self._strip(lo, hi)
            if hi - lo == 1 and self.t[lo].kind in ("str", "shell"):
                for kind, item in self.t[lo].parts:
                    if kind == "text":
                        quote = _advance_quote(quote, item)
                    else:
                        out |= _in_quote(self._eval_tokens(item, st), quote)
            else:
                out |= _in_quote(self.eval(lo, hi, st), quote)
        return _cap(frozenset(out))

    def _eval_tokens(self, toks: tuple, st) -> frozenset:
        sub = _Analyzer(list(toks))
        sub.hits, sub.consts = self.hits, self.consts
        return sub.eval(0, len(toks), st)

    def _unary(self, lo: int, hi: int, st) -> frozenset:
        tok = self.t[lo]
        if tok.kind == "op":
            if tok.text in ("!", "-", "+", "~", "++", "--"):
                self.eval(lo + 1, hi, st)
                return EMPTY
            if tok.text in ("@", "&", "..."):
                return self.eval(lo + 1, hi, st)
        if tok.kind == "cast":
            value = self.eval(lo + 1, hi, st)
            return EMPTY if tok.text in _SCALAR_CASTS else value
        if tok.kind == "name":
            word = tok.text.lower()
            if word in (
                "new",
                "clone",
                "yield",
                "throw",
                "print",
                "include",
                "include_once",
                "require",
                "require_once",
            ):
                if word == "new" and self._word(lo + 1, "class"):
                    k = next((j for j in range(lo, hi) if self._op(j, "{")), None)
                    if k is not None:
                        self._class_body(k + 1, self._close(k, hi))
                    return EMPTY
                value = self.eval(lo + 1, hi, st)
                return value if word in ("new", "clone", "yield") else EMPTY
            if word in ("function", "fn") or (word == "static" and self._word(lo + 1, "function", "fn")):
                return self._closure(lo, hi, st)
            if word == "match" and self._op(lo + 1, "("):
                return self._match(lo, hi, st)
            if word in ("exit", "die", "isset", "empty"):
                if self._op(lo + 1, "("):
                    self.eval(lo + 2, self._close(lo + 1, hi), st)
                return EMPTY
        return self._chain(lo, hi, st)

    def _closure(self, lo: int, hi: int, st) -> frozenset:
        k = lo + 1 if self._word(lo, "static") else lo
        if self._word(k, "fn"):
            arrow = next((j for j in self._top(k, hi) if self._op(j, "=>")), None)
            if arrow is not None:
                self.eval(arrow + 1, hi, dict(st))
            return EMPTY
        inherited = {}
        use = next((j for j in self._top(k, hi) if self._word(j, "use")), None)
        if use is not None and self._op(use + 1, "("):
            for j in range(use + 2, self._close(use + 1, hi)):
                if self._is(j, "var") and self.t[j].text in st:
                    inherited[self.t[j].text] = st[self.t[j].text]
        self._function(k, hi, inherited)
        return EMPTY

    def _match(self, lo: int, hi: int, st) -> frozenset:
        rp = self._close(lo + 1, hi)
        self.eval(lo + 2, rp, st)
        if not self._op(rp + 1, "{"):
            return EMPTY
        rb = self._close(rp + 1, hi)
        out = EMPTY
        for a, b in self._split(rp + 2, rb, {","}):
            arrow = next((j for j in self._top(a, b) if self._op(j, "=>")), None)
            if arrow is not None:
                out = _cap(out | self.eval(arrow + 1, b, st))
        return out

    def _chain(self, lo: int, hi: int, st) -> frozenset:
        """A primary expression and its `[…]`, `->m(…)`, `::m(…)` and call suffixes."""
        tok = self.t[lo]
        i = lo + 1
        request = False
        if tok.kind == "var":
            if tok.text in _SUPERGLOBALS or (tok.text == "_SERVER" and self._server_key(i, hi)):
                field = self._field_key(tok.text, i)
                value = st[field] if field in st else _source(tok.line)
                if tok.text == "_FILES" and self._file_field(i, hi) in _SERVER_SET_FILE_KEYS:
                    value = EMPTY
            elif tok.text == "_SERVER":
                value = EMPTY
            elif tok.text in _REQUEST_VARS:
                value, request = EMPTY, True
            else:
                value = st.get(tok.text, EMPTY)
        elif self._op(lo, "[") or (self._word(lo, "array") and self._op(lo + 1, "(")):
            open_ = lo if self._op(lo, "[") else lo + 1
            close = self._close(open_, hi)
            value = EMPTY
            for a, b in self._split(open_ + 1, close, {","}):
                for x, y in self._split(a, b, {"=>"}):
                    value = _cap(value | self.eval(x, y, st))
            i = close + 1
        elif tok.kind == "name":
            if self._op(i, "("):
                rp = self._close(i, hi)
                value, request = self._call(tok.text, i, rp, tok.line, st)
                i = rp + 1
            elif self._op(i, "::") and i + 1 < hi:
                member = self.t[i + 1]
                if self._op(i + 2, "("):
                    rp = self._close(i + 2, hi)
                    value = self._static(tok.text, member.text, i + 2, rp, member.line, st)
                    i = rp + 1
                else:
                    value, i = EMPTY, i + 2
            else:
                value = EMPTY
        elif tok.kind == "str":
            value = self._concat([(lo, lo + 1)], st)
        elif tok.kind == "shell":
            self._hit(SHELL, self._concat([(lo, lo + 1)], st), tok.line)
            value = EMPTY
        elif self._op(lo, "(") and lo in self.m:
            close = self._close(lo, hi)
            value = self.eval(lo + 1, close, st)
            i = close + 1
        else:
            value = EMPTY
        while i < hi:
            if self._op(i, "[", "{") and i in self.m:
                close = self._close(i, hi)
                self.eval(i + 1, close, st)
                i = close + 1
            elif self._op(i, "->", "?->") and i + 1 < hi:
                member = self.t[i + 1]
                call = self._op(i + 2, "(")
                rp = self._close(i + 2, hi) if call else i + 1
                if request:
                    if call:
                        for a, b in self._args(i + 2, rp):
                            self.eval(a, b, st)
                    clean = call and member.kind == "name" and member.text.lower() in _REQUEST_CLEAN
                    value, request = (EMPTY if clean else _source(member.line)), False
                elif call:
                    value = self._method(
                        member.text if member.kind == "name" else "", value, i + 2, rp, member.line, st
                    )
                i = rp + 1
            elif self._op(i, "::") and i + 1 < hi:
                if self._op(i + 2, "("):
                    rp = self._close(i + 2, hi)
                    value = _cap(value | self._args_value(i + 2, rp, st))
                    i = rp + 1
                else:
                    i += 2
            elif self._op(i, "("):
                rp = self._close(i, hi)
                value = _cap(value | self._args_value(i, rp, st))
                i = rp + 1
            elif self._op(i, "++", "--"):
                return EMPTY
            else:
                break
        return value

    def _field_key(self, name: str, i: int) -> str | None:
        """`$_GET[id]` for `$_GET['id']`: the key under which a check of that field is recorded."""
        if self._op(i, "[") and self._is(i + 1, "str") and self._op(i + 2, "]"):
            return f"${name}[{self._const_text(i + 1, i + 2)}]"
        return None

    def _file_field(self, i: int, hi: int) -> str | None:
        if self._op(i, "[") and i in self.m:
            j = self.m[i] + 1
            if self._op(j, "[") and j + 1 < hi and self.t[j + 1].kind == "str":
                return self.t[j + 1].text
        return None

    def _server_key(self, i: int, hi: int) -> bool:
        if self._op(i, "[") and i + 1 < hi and self.t[i + 1].kind == "str":
            key = self.t[i + 1].text.upper()
            return key in _SERVER_KEYS or key.startswith("HTTP_")
        return False

    def _args_value(self, lp: int, rp: int, st) -> frozenset:
        value = EMPTY
        for a, b in self._args(lp, rp):
            value = _cap(value | self.eval(a, b, st))
        return value

    def _arg_at(self, args: list, index: int):
        if not args:
            return None
        if index < 0:
            return args[index] if len(args) >= -index else args[0]
        return args[index] if index < len(args) else None

    def _call(self, name: str, lp: int, rp: int, line: int, st) -> tuple[frozenset, bool]:
        func = name.rsplit("\\", 1)[-1].lower()
        args = self._args(lp, rp)
        if func == "request":
            if args:
                self._args_value(lp, rp, st)
                return _source(line), False
            return EMPTY, True
        if func in ("getallheaders", "apache_request_headers", "filter_input_array"):
            return _source(line), False
        if func in ("file_get_contents", "fopen") and args and self._const_text(*args[0]) == "php://input":
            return _source(line), False
        if func == "filter_input":
            filter_name = self._filter_name(*args[2]) if len(args) >= 3 else None
            return self._filtered(_source(line), filter_name), False
        if func == "sprintf" or func == "vsprintf":
            return self._sprintf(args, st, single_array=func == "vsprintf"), False
        values = [self.eval(a, b, st) for a, b in args]
        if func == "array_map" and args and (self._const_text(*args[0]) or "").lower() in _CLEAN_FUNCS:
            return EMPTY, False
        if func in _SQL_FUNCS:
            index = _SQL_FUNCS[func]
            if func == "pg_query_params" and len(args) < 3:
                index = 0
            target = self._arg_at(list(range(len(args))), index)
            if target is not None:
                self._hit(SQL, values[target], line)
            return EMPTY, False
        if func in _SHELL_FUNCS:
            if args and not (self._op(args[0][0], "[") or self._word(args[0][0], "array")):
                self._hit(SHELL, values[0], line)
            return EMPTY, False
        if func in _ESCAPERS:
            index, state = _ESCAPERS[func]
            target = self._arg_at(list(range(len(args))), index)
            return (_with_state(values[target], state) if target is not None else EMPTY), False
        if func in ("htmlspecialchars", "htmlentities"):
            quotes = len(args) < 2 or any(self._is(j, "name", "ENT_QUOTES") for j in range(args[1][0], args[1][1]))
            return (_with_state(values[0], "noquote") if quotes else values[0]) if values else EMPTY, False
        if func == "filter_var" and values:
            filter_name = self._filter_name(*args[1]) if len(args) >= 2 else None
            return self._filtered(values[0], filter_name), False
        if func in ("preg_replace", "preg_replace_callback") and len(args) >= 3:
            pattern, replacement = self._const_text(*args[0]), self._const_text(*args[1])
            state = _removal_state(pattern) if pattern is not None and replacement == "" else None
            if state == "clean":
                return EMPTY, False
            return (_with_state(values[2], state) if state else _cap(values[1] | values[2])), False
        if func == "settype" and len(args) >= 2:
            kind = (self._const_text(*args[1]) or "").lower()
            name = self._base_name(*args[0])
            if kind in _SETTYPE_SCALARS and name:
                st.update(_cleaned(st, {name}))
                if not name.startswith("$"):
                    st.pop(name, None)
            return EMPTY, False
        if func == "parse_str" and len(args) >= 2:
            name = self._base_name(*args[1])
            if name and values[0]:
                st[name] = values[0]
            return EMPTY, False
        if func in _CLEAN_FUNCS or func.startswith(_CLEAN_PREFIXES):
            return EMPTY, False
        if func in _DECODERS:
            return (_with_state(_cap(frozenset().union(*values)), "raw") if values else EMPTY), False
        return (_cap(frozenset().union(*values)) if values else EMPTY), False

    def _filtered(self, value: frozenset, filter_name: str | None) -> frozenset:
        if filter_name in _SAFE_FILTERS:
            return EMPTY
        state = _FILTER_STATES.get(filter_name or "")
        return _with_state(value, state) if state else value

    def _sprintf(self, args: list, st, single_array: bool = False) -> frozenset:
        values = [self.eval(a, b, st) for a, b in args]
        if single_array and len(values) == 2:
            values = values + [values[1]] * 32  # vsprintf: every conversion reads the one array
        fmt = self._const_text(*args[0]) if args else None
        if fmt is None:
            return _cap(frozenset().union(*values)) if values else EMPTY
        out, quote, n, i = set(), None, 1, 0
        spec = re.compile(r"%(?:(\d+)\$)?[-+ 0]*(?:'.)?\d*(?:\.\d+)?([bcdeEfFgGosuxX%])")
        while i < len(fmt):
            m = spec.match(fmt, i) if fmt[i] == "%" else None
            if not m:
                quote = _advance_quote(quote, fmt[i])
                i += 1
                continue
            i = m.end()
            if m.group(2) == "%":
                continue
            index = int(m.group(1)) if m.group(1) else n
            n += 0 if m.group(1) else 1
            if m.group(2) == "s" and index < len(values):
                out |= _in_quote(values[index], quote)
        return _cap(frozenset(out))

    def _method(self, name: str, receiver: frozenset, lp: int, rp: int, line: int, st) -> frozenset:
        method = name.lower()
        args = self._args(lp, rp)
        values = [self.eval(a, b, st) for a, b in args]
        if method in _SQL_METHODS:
            if values:
                self._hit(SQL, values[0], line)
            return EMPTY
        if method in _ESCAPER_METHODS and values:
            return _with_state(values[0], _ESCAPER_METHODS[method])
        return _cap(receiver.union(*values)) if values else receiver

    def _static(self, cls: str, member: str, lp: int, rp: int, line: int, st) -> frozenset:
        cls_name, method = cls.rsplit("\\", 1)[-1].lower(), member.lower()
        args = self._args(lp, rp)
        values = [self.eval(a, b, st) for a, b in args]
        if method in _SQL_STATIC.get(cls_name, ()) or method in _RAW_BUILDER_METHODS:
            if values:
                self._hit(SQL, values[0], line)
            return EMPTY
        if method in _SHELL_STATIC.get(cls_name, ()):
            if args and not (self._op(args[0][0], "[") or self._word(args[0][0], "array")):
                self._hit(SHELL, values[0], line)
            return EMPTY
        if cls_name in _REQUEST_FACADES and method in _FACADE_SOURCE_METHODS:
            return _source(line)
        if cls_name == "sqlite3" and method == "escapestring" and values:
            return _with_state(values[0], "escaped")
        return _cap(frozenset().union(*values)) if values else EMPTY


def _pieces(lo: int, hi: int, cuts: list[int]) -> list[tuple[int, int]]:
    bounds = [lo - 1, *cuts, hi]
    return [(a + 1, b) for a, b in zip(bounds, bounds[1:])]


def _advance_quote(quote: str | None, text: str) -> str | None:
    """The SQL or shell quote open after `text`, starting inside `quote`."""
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if quote is None:
            if ch in "'\"":
                quote = ch
        elif ch == "\\" and quote == '"':
            i += 1
        elif ch == "\\" and quote == "'" and i + 1 < n and text[i + 1] == "'":
            i += 1
        elif ch == quote:
            quote = None
        i += 1
    return quote
