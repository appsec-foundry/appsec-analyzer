"""Bounded source-use evidence for route extraction, never source admission.

Only module-relative text reads ending in a recognized JSON response can
exclude a file's apparent server registrations. Imports, entry points and
ambiguous loading take precedence. Other analyses retain every source file.
No repository code, manifest command or model response is executed here.
"""

from __future__ import annotations

import ast
import bisect
import json
import posixpath
import re
from collections import Counter
from pathlib import Path
from typing import Iterable, Mapping

from shared._path_guard import is_safe_to_read
from shared._source_lex import call_end, code_only, without_comments

from analyzers.handler_resolver import _split_args, direct_imports, js_module_candidates

MAX_FILES = 4096
MAX_BYTES = 16 * 1024 * 1024
MAX_FILE_BYTES = 1_000_000
MAX_READS = 32
MAX_PYTHON_NODES = 20_000
MAX_HELPERS = 32
MAX_HELPER_DEPTH = 3
MAX_HELPER_BODY = 4096
_JS = {".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs"}
_METADATA = {
    ".md",
    ".markdown",
    ".rst",
    ".txt",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
}
_DOCUMENTS = {".md", ".markdown", ".rst", ".txt"}
_PATH_TOKEN = re.compile(r"(?<![\w./])(?:\.\.?/)?[\w@-][\w@./-]*")
_EXECUTION_KEY = re.compile(
    r"(?:^|[\n{,])[^\S\n]*(?:-[^\S\n]*)?['\"]?(?:scripts?|run|command|entrypoint|main|module|exports|bin)['\"]?[^\S\n]*[:=]",
    re.MULTILINE,
)
_STRINGS = re.compile(r"""'(?:[^'\\\n]|\\.)*'|"(?:[^"\\\n]|\\.)*""")
_READ = re.compile(r"\b(?P<module>[A-Za-z_$][\w$]*)\.(?P<method>readFileSync|readFile)\s*\(")
_CALLBACK = re.compile(
    r"\b(?P<app>[A-Za-z_$][\w$]*)\.(?:get|post|put|patch|delete|all)\s*\(\s*"
    r"(['\"])[^'\"\n]*\2\s*,\s*(?:async\s*)?\(\s*[A-Za-z_$][\w$]*\s*,\s*(?P<response>[A-Za-z_$][\w$]*)\s*\)\s*=>\s*(?P<brace>\{)"
)


def _literal(value: str) -> str | None:
    try:
        result = ast.literal_eval(value)
        return result if isinstance(result, str) and "\x00" not in result else None
    except (ValueError, SyntaxError):
        return None


def _relative(folder: str, value: str) -> str | None:
    if not value or value.startswith(("/", "\\")) or "\\" in value or ":" in value:
        return None
    path = posixpath.normpath(posixpath.join(folder, value))
    return path if path != ".." and not path.startswith("../") else None


def _role(kind: str, reason: str, file: str | None = None, line: int = 1) -> dict:
    return {"kind": kind, "reason": reason, "evidence": [] if file is None else [{"file": file, "line": line}]}


def _bindings(text: str, package: str) -> set[str]:
    package = re.escape(package)
    syntax = code_only(text)
    return {
        next(value for value in match.groups() if value)
        for match in re.finditer(
            rf"\bimport\s+(\w+)\s+from\s*['\"](?:node:)?{package}['\"]"
            rf"|\b(?:const|let)\s+(\w+)\s*=\s*require\(['\"](?:node:)?{package}['\"]\)",
            text,
        )
        if not syntax[match.start()].isspace()
    }


def _js_string(expression: str, values: Mapping[str, str]) -> str | None:
    """Fold a small string-only expression; never evaluate repository code."""
    if len(expression) > MAX_HELPER_BODY:
        return None
    if expression.startswith("`") and expression.endswith("`"):
        body = expression[1:-1]
        if "\\" in body or "`" in body:
            return None
        pieces, start = [], 0
        for match in re.finditer(r"\$\{([^{}]+)\}", body):
            value = _js_string(match[1], values)
            if value is None:
                return None
            pieces.extend([body[start : match.start()], value])
            start = match.end()
        pieces.append(body[start:])
        result = "".join(pieces)
        return result if len(result) <= MAX_HELPER_BODY and "${" not in result and "\x00" not in result else None
    try:
        tree = ast.parse(expression, mode="eval")
        nodes = list(ast.walk(tree))
        if len(nodes) > 64:
            return None

        def fold(node, depth=0):
            if depth > 8:
                return None
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                token = ast.get_source_segment(expression, node)
                # Python's parser also accepts prefixes, adjacent literals
                # and escape forms with different JavaScript semantics.
                return node.value if token and _STRINGS.fullmatch(token) and "\\" not in token else None
            if isinstance(node, ast.Name):
                return values.get(node.id)
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                left, right = fold(node.left, depth + 1), fold(node.right, depth + 1)
                if left is not None and right is not None:
                    return left + right
            return None

        result = fold(tree.body)
        return result if result is not None and len(result) <= MAX_HELPER_BODY and "\x00" not in result else None
    except (SyntaxError, ValueError, RecursionError):
        return None


def _js_path(expression: str, file: str, path_modules: set[str], values: Mapping[str, str] | None = None) -> str | None:
    values = values or {}
    match = re.fullmatch(r"new\s+URL\(([\s\S]*)\)", expression)
    args = _split_args(match[1]) if match else []
    if len(args) == 2 and args[1] == "import.meta.url":
        value = _js_string(args[0], values)
        return (
            None if value is None or any(char in value for char in "%?#") else _relative(posixpath.dirname(file), value)
        )
    match = re.fullmatch(r"(\w+)\.join\(\s*__dirname\s*,([\s\S]*)\)", expression)
    if match and match[1] in path_modules:
        parts = [_js_string(part, values) for part in _split_args(match[2])]
        if parts and all(part is not None for part in parts):
            return _relative(posixpath.dirname(file), "/".join(parts))
    return None


def _js_helpers(text: str, syntax: str) -> dict[str, dict] | None:
    """Private module-level helpers with a single return expression, capped before tracing."""
    declarations = re.compile(
        r"(?m)^[ \t]*(?:function\s+(?P<function>[A-Za-z_$][\w$]*)\s*\((?P<fp>[^()\n]*)\)"
        r"|const\s+(?P<arrow>[A-Za-z_$][\w$]*)\s*=\s*(?:\((?P<ap>[^()\n]*)\)|(?P<single>[A-Za-z_$][\w$]*))\s*(?::\s*string)?\s*=>)"
        r"\s*(?::\s*string)?\s*"
    )
    helpers = {}
    for number, match in enumerate(declarations.finditer(text)):
        if number >= MAX_HELPERS:
            return None
        if syntax[match.start()].isspace() and not syntax[match.start() : match.end()].strip():
            continue
        if syntax.count("{", 0, match.start()) != syntax.count("}", 0, match.start()):
            continue
        name = match["function"] or match["arrow"]
        params = _split_args(
            match["fp"] if match["function"] else match["ap"] if match["ap"] is not None else match["single"]
        )
        if len(params) > 4 or any(not re.fullmatch(r"[A-Za-z_$][\w$]*(?:\s*:\s*string)?", param) for param in params):
            continue
        params = [param.split(":")[0].strip() for param in params]
        if len(set(params)) != len(params):
            continue
        start = match.end()
        if start >= len(text):
            continue
        if text[start] == "{":
            # Only inspect a bounded body; unmatched or longer helpers stay unknown.
            stop = start + 1
            depth = 1
            while stop < min(len(text), start + MAX_HELPER_BODY) and depth:
                depth += (syntax[stop] == "{") - (syntax[stop] == "}")
                stop += 1
            if depth:
                continue
            returned = re.fullmatch(r"\s*return[ \t]+([\s\S]*?);?\s*", text[start + 1 : stop - 1])
            if returned is None or returned[1].startswith(("\r", "\n")):
                continue
            expression = returned[1].rstrip(";").strip()
            expr_start = start + 1 + returned.start(1)
        elif match["arrow"]:
            stop = text.find("\n", start)
            stop = len(text) if stop < 0 else stop
            if stop - start > MAX_HELPER_BODY:
                continue
            expression = text[start:stop].rstrip().rstrip(";").strip()
            expr_start = start
        else:
            continue
        if not re.match(r"[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?\s*\(", expression):
            continue
        if name in helpers or len(helpers) >= MAX_HELPERS:
            return None
        helpers[name] = {
            "params": params,
            "expression": expression,
            "start": expr_start,
            "name_span": match.span("function" if match["function"] else "arrow"),
        }
    return helpers


def _js_helper_reads(file, text, syntax, fs, paths, handlers, ends):
    if not fs or not _READ.search(text):
        return [], False
    helpers = _js_helpers(text, syntax)
    if helpers is None:
        return [], True

    def bounded_end(value, opening):
        fragment = value[opening : opening + MAX_HELPER_BODY]
        end = call_end(fragment, 0)
        code = code_only(fragment[:end])
        return opening + end if code.count("(") == code.count(")") else None

    def resolve(name, arguments, depth=0, seen=frozenset()):
        if depth >= MAX_HELPER_DEPTH or name in seen or name not in helpers:
            return None
        helper = helpers[name]
        if len(arguments) != len(helper["params"]) or any(value is None for value in arguments):
            return None
        values = dict(zip(helper["params"], arguments))
        expression = helper["expression"]
        call = re.match(r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)?)\s*\(", expression)
        end = bounded_end(expression, call.end() - 1)
        if end is None or expression[end:].strip():
            return None
        args = _split_args(expression[call.end() : end - 1])
        callee = call[1]
        span = (helper["start"], helper["start"] + end)
        if callee in helpers:
            inner = resolve(callee, [_js_string(arg, values) for arg in args], depth + 1, seen | {name})
            return None if inner is None else (inner[0], inner[1], [span, *inner[2]], {name, *inner[3]})
        module, _, method = callee.partition(".")
        if (
            module not in fs
            or method != "readFileSync"
            or len(args) != 2
            or _js_string(args[1], {}) not in {"utf8", "utf-8"}
        ):
            return None
        path = _js_path(args[0], file, paths, values)
        return None if path is None else (path, module, [span], {name})

    found, allowed, used = [], [], set()
    calls = 0
    for name, helper in helpers.items():
        for call in re.finditer(rf"\b{re.escape(name)}\s*\(", text):
            if syntax[call.start()].isspace() or call.start() == helper["name_span"][0]:
                continue
            if any(h["start"] <= call.start() < h["start"] + len(h["expression"]) for h in helpers.values()):
                continue
            calls += 1
            if calls > MAX_READS:
                return [], True
            end = bounded_end(text, call.end() - 1)
            if end is None:
                continue
            args = [_js_string(arg, {}) for arg in _split_args(text[call.end() : end - 1])]
            resolved = resolve(name, args)
            if resolved is None:
                continue
            path, module, spans, chain = resolved
            if not _js_passive(text, call, end, module, syntax, handlers, ends):
                return [], True
            spans = [(call.start(), end), *spans]
            found.extend((path, start, stop) for start, stop in spans)
            allowed.extend(spans)
            used |= chain
    for name in used:
        spans = [helpers[name]["name_span"], *allowed]
        if any(
            not any(start <= match.start() < stop for start, stop in spans)
            for match in re.finditer(rf"\b{re.escape(name)}\b", syntax)
        ):
            return [], True
    return found, False


def _handler_ends(syntax: str, handlers: list) -> dict[int, int] | None:
    """Match callback braces once; excessive nesting or malformed braces are unknown."""
    wanted = {handler.start("brace") for handler in handlers}
    stack, ends = [], {}
    for index, char in enumerate(syntax):
        if char == "{":
            stack.append(index)
            if len(stack) > 1000:
                return None
        elif char == "}":
            if not stack:
                return None
            start = stack.pop()
            if start in wanted:
                ends[start] = index + 1
    return None if stack else ends


def _js_passive(text: str, read, end: int, module: str, syntax: str, handlers: list, ends: dict) -> bool:
    """A local string is used only in plain JSON data in an inline Express callback."""
    if syntax[read.start()].isspace():
        return False
    # A reassigned or shadowed standard binding cannot establish a text read.
    if len(re.findall(rf"\b{re.escape(module)}\s*=", syntax)) > 1 or re.search(
        rf"\b{re.escape(module)}\.\w+\s*=", syntax
    ):
        return False
    if re.search(r"\b(?:eval|Function|compileFunction|runInContext|runInNewContext|runInThisContext)\b", syntax):
        return False
    if re.search(r"\.(?:json|response)\s*=|\bObject\.(?:assign|defineProperty)\s*\(", syntax):
        return False
    apps = set()
    for name in _bindings(text, "express"):
        apps.update(
            match[1]
            for match in re.finditer(rf"\bconst\s+(\w+)\s*=\s*{re.escape(name)}(?:\.Router)?\(\s*\)", text)
            if not syntax[match.start()].isspace()
        )
    for handler in handlers:
        if handler["app"] not in apps or syntax[handler.start()].isspace():
            continue
        if re.search(rf"(?:\(|,)\s*{re.escape(handler['app'])}\s*[,)]", syntax):
            continue
        if re.search(rf"\b{re.escape(handler['app'])}\.use\s*\(", syntax):
            continue
        start = handler.start("brace")
        stop = ends.get(start, start)
        if not start < read.start() < end < stop:
            continue
        prefix = text[start : read.start()]
        assignment = re.search(r"\bconst\s+(\w+)(?:\s*:\s*string)?\s*=\s*(?:await\s+)?$", prefix)
        if assignment is None or not re.match(r"\s*;?\s*(?:\n|$)", text[end:]):
            continue
        value, response = assignment[1], handler["response"]
        safe = []
        pattern = re.compile(rf"\b{re.escape(response)}(?:\.status\(\s*\d{{3}}\s*\))?\.json\s*\(")
        for output in pattern.finditer(text, end, stop):
            close = call_end(text, output.end() - 1)
            arguments = text[output.end() : close - 1]
            if "(" not in code_only(arguments) and "`" not in arguments and "..." not in arguments:
                safe.append((output.end(), close))
        uses = list(re.finditer(rf"\b{re.escape(value)}\b", syntax[end:stop]))
        response_uses = list(re.finditer(rf"\b{re.escape(response)}\b", syntax[start:stop]))
        output_spans = [
            (match.start(), call_end(text, match.end() - 1)) for match in pattern.finditer(text, start, stop)
        ]
        response_safe = all(
            any(first <= start + use.start() < last for first, last in output_spans) for use in response_uses
        )
        if (
            response_safe
            and uses
            and all(any(first <= end + use.start() < last for first, last in safe) for use in uses)
        ):
            return True
    return False


def _js_reads(file: str, text: str) -> tuple[list[tuple[str, int, int]], bool]:
    fs, promises = _bindings(text, "fs"), _bindings(text, "fs/promises")
    paths = _bindings(text, "path")
    reads, ambiguous = [], False
    calls = list(_READ.finditer(text))
    handlers = list(_CALLBACK.finditer(text))
    if len(calls) > MAX_READS or len(handlers) > 64:
        return [], True
    intervals = [(match.start(), call_end(text, match.end() - 1)) for match in calls]
    syntax = code_only(text)
    ends = _handler_ends(syntax, handlers)
    if ends is None:
        return [], True
    for alias in fs | promises | paths | _bindings(text, "express"):
        allowed = list(intervals)
        allowed += [
            match.span()
            for match in re.finditer(
                rf"\bimport\s+{re.escape(alias)}\s+from[^;\n]+|\b(?:const|let)\s+{re.escape(alias)}\s*=\s*require\([^)]*\)",
                text,
            )
        ]
        if alias in _bindings(text, "express"):
            allowed += [match.span() for match in re.finditer(rf"\b{re.escape(alias)}(?:\.Router)?\(\s*\)", text)]
        if any(
            not any(start <= use.start() < end for start, end in allowed)
            for use in re.finditer(rf"\b{re.escape(alias)}\b", syntax)
        ):
            ambiguous = True
    if re.search(
        r"\b(?:const|let|var|function|class|import)\s+(?:URL|__dirname)\b|\b(?:URL|__dirname)\s*="
        r"|\([^)]*\b(?:URL|__dirname)\b[^)]*\)\s*=>|function\s*\w*\([^)]*\b(?:URL|__dirname)\b",
        syntax,
    ):
        ambiguous = True
    helper_reads, unknown_helpers = _js_helper_reads(file, text, syntax, fs, paths, handlers, ends)
    reads.extend(helper_reads)
    ambiguous |= unknown_helpers
    for match in calls:
        if any(start <= match.start() < end for _, start, end in helper_reads):
            continue
        if match["module"] not in fs | promises:
            continue
        end = call_end(text, match.end() - 1)
        args = _split_args(text[match.end() : end - 1])
        path = _js_path(args[0], file, paths) if args else None
        if path is None:
            ambiguous = True
            continue
        sync = match["method"] == "readFileSync" and match["module"] in fs
        awaited = match["module"] in promises and bool(re.search(r"\bawait\s*$", text[: match.start()]))
        if (sync or awaited) and len(args) == 2 and _literal(args[1]) in {"utf8", "utf-8"}:
            if _js_passive(text, match, end, match["module"], syntax, handlers, ends):
                reads.append((path, match.start(), end))
    return reads, ambiguous


def _python_path(node, file: str, paths: set[str]) -> str | None:
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "with_name":
        if len(node.args) == 1 and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str):
            if "/" in node.args[0].value or node.args[0].value in {"", ".", ".."}:
                return None
            base = _python_path(node.func.value, file, paths)
            return None if base is None else _relative(posixpath.dirname(base), node.args[0].value)
    if isinstance(node, ast.Attribute) and node.attr == "parent":
        base = _python_path(node.value, file, paths)
        return None if not base else posixpath.dirname(base)
    if (
        isinstance(node, ast.BinOp)
        and isinstance(node.op, ast.Div)
        and isinstance(node.right, ast.Constant)
        and isinstance(node.right.value, str)
    ):
        base = _python_path(node.left, file, paths)
        return None if base is None else _relative(base, node.right.value)
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in paths:
        if len(node.args) == 1 and isinstance(node.args[0], ast.Name) and node.args[0].id == "__file__":
            return file
    return None


def _python_reads(file: str, text: str) -> tuple[list[tuple[str, int, int]], bool]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, RecursionError):
        return [], True
    nodes = []
    for node in ast.walk(tree):
        nodes.append(node)
        if len(nodes) > MAX_PYTHON_NODES:
            return [], True
    if (
        sum(
            isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "read_text"
            for node in nodes
        )
        > MAX_READS
    ):
        return [], True
    paths, responses, factories = set(), set(), set()
    for node in tree.body:
        if isinstance(node, ast.ImportFrom) and node.module == "pathlib":
            paths.update(item.asname or item.name for item in node.names if item.name == "Path")
        if isinstance(node, ast.ImportFrom) and node.module == "flask":
            responses.update(item.asname or item.name for item in node.names if item.name == "jsonify")
            factories.update(item.asname or item.name for item in node.names if item.name == "Flask")
    apps = {
        node.targets[0].id
        for node in tree.body
        if isinstance(node, ast.Assign)
        and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
        and isinstance(node.value, ast.Call)
        and isinstance(node.value.func, ast.Name)
        and node.value.func.id in factories
    }
    bound = Counter()
    for node in nodes:
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            bound[node.id] += 1
        elif isinstance(node, ast.arg):
            bound[node.arg] += 1
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound[node.name] += 1
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            bound.update(item.asname or item.name.split(".")[0] for item in node.names)
    call_funcs = {id(node.func) for node in nodes if isinstance(node, ast.Call)}
    shadowed = "__file__" in bound or any(bound[alias] != 1 for alias in paths | responses | factories | apps)
    shadowed |= any(isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Store) for node in nodes)
    shadowed |= any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id in apps
        and node.func.attr not in {"get", "post", "put", "delete", "patch", "route", "run"}
        for node in nodes
    )
    shadowed |= any(
        isinstance(node, ast.Name)
        and isinstance(node.ctx, ast.Load)
        and node.id in responses | paths | factories
        and id(node) not in call_funcs
        for node in nodes
    )
    reads, ambiguous = [], False
    lines = text.splitlines(keepends=True)
    offsets = [0]
    for line in lines:
        offsets.append(offsets[-1] + len(line))

    def offset(line, column):
        return offsets[line - 1] + len(lines[line - 1].encode("utf-8")[:column].decode("utf-8"))

    for function in ast.walk(tree):
        if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        handler = any(
            isinstance(d, ast.Call)
            and isinstance(d.func, ast.Attribute)
            and isinstance(d.func.value, ast.Name)
            and d.func.value.id in apps
            and d.func.attr in {"get", "post", "route", "put", "delete"}
            for d in function.decorator_list
        )
        for assign in ast.walk(function):
            if (
                not isinstance(assign, ast.Assign)
                or len(assign.targets) != 1
                or not isinstance(assign.targets[0], ast.Name)
            ):
                continue
            call = assign.value
            if (
                not isinstance(call, ast.Call)
                or not isinstance(call.func, ast.Attribute)
                or call.func.attr != "read_text"
            ):
                continue
            path = _python_path(call.func.value, file, paths)
            if path is None:
                ambiguous = True
                continue
            name = assign.targets[0].id
            safe = set()
            for node in ast.walk(function):
                if (
                    not isinstance(node, ast.Return)
                    or not isinstance(node.value, ast.Call)
                    or not isinstance(node.value.func, ast.Name)
                    or node.value.func.id not in responses
                    or any(kw.arg is None for kw in node.value.keywords)
                ):
                    continue
                data = [*node.value.args, *(kw.value for kw in node.value.keywords)]
                if all(
                    isinstance(part, (ast.Dict, ast.List, ast.Tuple, ast.Name, ast.Constant, ast.Load))
                    for value in data
                    for part in ast.walk(value)
                ):
                    safe.update(id(part) for value in data for part in ast.walk(value) if isinstance(part, ast.Name))
            uses = [
                node
                for node in ast.walk(function)
                if isinstance(node, ast.Name) and node.id == name and isinstance(node.ctx, ast.Load)
            ]
            simple_read = not call.args and all(
                kw.arg == "encoding" and isinstance(kw.value, ast.Constant) and kw.value.value in {"utf8", "utf-8"}
                for kw in call.keywords
            )
            if handler and simple_read and not shadowed and uses and all(id(node) in safe for node in uses):
                reads.append(
                    (
                        path,
                        offset(call.lineno, call.col_offset),
                        offset(call.end_lineno, call.end_col_offset),
                    )
                )
    return reads, ambiguous


def _module_references(file: str, text: str, sources: Mapping[str, str]) -> set[str]:
    """Include side-effect imports, re-exports and Python imported submodules."""
    found = set(direct_imports(file, text, lambda candidate: candidate in sources))
    folder = posixpath.dirname(file)
    if Path(file).suffix.lower() in _JS:
        pattern = r"\b(?:import\s*(?:\(\s*)?|(?:import|export)\s+[^;\n]*?\bfrom\s*|require\s*\(\s*)['\"]([^'\"]+)['\"]"
        for match in re.finditer(pattern, text):
            if match[1].startswith("."):
                base = _relative(folder, match[1])
                if base:
                    found.update(candidate for candidate in js_module_candidates(base) if candidate in sources)
    elif file.endswith(".py"):
        try:
            tree = ast.parse(text)
        except (SyntaxError, RecursionError):
            return found
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
                roots = ["", "src", folder]
            elif isinstance(node, ast.ImportFrom):
                module = (node.module or "").replace(".", "/")
                names = [module, *(posixpath.join(module, alias.name) for alias in node.names)]
                base = folder
                for _ in range(max(0, node.level - 1)):
                    base = posixpath.dirname(base)
                roots = [base] if node.level else ["", "src", folder]
            else:
                continue
            for name in names:
                for root in roots:
                    stem = posixpath.join(root, name.replace(".", "/"))
                    found.update(
                        candidate
                        for candidate in (stem + ".py", posixpath.join(stem, "__init__.py"))
                        if candidate in sources
                    )
    return found


def classify(sources: Mapping[str, str], *, entries: Iterable[str] = (), complete: bool = True) -> dict[str, dict]:
    """Classify observed use as runtime, text-data or unknown; runtime always wins."""
    roles = {file: _role("unknown", "No complete text-only use was established") for file in sources}
    sizes = [len(text.encode()) for text in sources.values()]
    if len(sources) > MAX_FILES or sum(sizes) > MAX_BYTES or any(size > MAX_FILE_BYTES for size in sizes):
        return roles
    runtime = {file: _role("runtime", "Declared program entry", file) for file in entries if file in sources}
    reads: dict[str, list[dict]] = {}
    accepted: dict[str, list[tuple[int, int]]] = {}
    texts = {}
    ambiguous = not complete
    for file, source in sources.items():
        suffix = Path(file).suffix.lower()
        if suffix in _METADATA and file not in runtime:
            # Metadata is reference evidence, not an unsupported language.
            # Keep launch paths (including unquoted YAML/TOML values) below;
            # uncertain configured execution still leaves candidates open.
            texts[file] = source
            ambiguous |= source.lstrip().startswith("#!")
            if suffix == ".toml":
                ambiguous |= any(
                    line.lstrip().startswith("[")
                    and any(key in line for key in ("scripts", "entry_points", "entry-points"))
                    for line in source.splitlines()
                )
            # Configured execution is not a traced text destination. A
            # command may invoke a loader even without dynamic syntax.
            if suffix not in _DOCUMENTS and _EXECUTION_KEY.search(source):
                ambiguous = True
            continue
        text = without_comments(source, python=suffix == ".py")
        texts[file] = text
        ambiguous |= suffix not in _JS | {".py", ".graphql", ".gql", ".graphqls"}
        for target in _module_references(file, text, sources):
            runtime[target] = _role("runtime", "Referenced as a program module", file)
            ambiguous |= Path(target).suffix.lower() in _METADATA
        if suffix in _JS:
            ambiguous |= bool(
                re.search(
                    r"\b(?:eval|Function|compileFunction|runInContext|runInNewContext|runInThisContext)\s*\(",
                    code_only(text),
                )
            )
            for load in re.finditer(r"\b(?:require|import)\s*\(", text):
                if not text[load.end() :].lstrip().startswith(("'", '"')):
                    ambiguous = True
            ambiguous |= bool(re.search(r"\b(?:require\.context|import\.meta\.glob|process\.chdir)\b", text))
            ambiguous |= bool(
                re.search(
                    r"\b(?:createRequire|exec|execSync|execFile|spawn|spawnSync)\s*\(",
                    code_only(text),
                )
            )
            ambiguous |= any(
                not re.match(r"\s*\(\s*['\"]", text[match.end() :])
                for match in re.finditer(r"\brequire\b", code_only(text))
            )
            found, unknown = _js_reads(file, text)
        elif suffix == ".py":
            ambiguous |= any(
                posixpath.join(folder, candidate) in sources
                for folder in {"", posixpath.dirname(file)}
                for candidate in {"pathlib.py", "pathlib/__init__.py", "flask.py", "flask/__init__.py"}
            )
            ambiguous |= bool(
                re.search(
                    r"\b(?:__import__|importlib|exec|eval|runpy|subprocess)\b|\bos\.(?:system|popen|exec\w*)\s*\(",
                    code_only(text),
                )
            )
            try:
                found, unknown = _python_reads(file, text)
            except (RecursionError, ValueError):
                found, unknown = [], True
            if re.search(r"\b__name__\s*==\s*['\"]__main__['\"]", text):
                runtime[file] = _role("runtime", "Standalone Python entry", file)
        else:
            found, unknown = [], False
        ambiguous |= unknown
        # Reads whose complete use could not be traced may feed another
        # loader. This also covers destructured fs calls and top-level reads.
        for read in re.finditer(
            r"\b(?:readFileSync|readFile|createReadStream|read_text|read_bytes|open)\s*\(", code_only(text)
        ):
            if not any(start <= read.start() < end for _, start, end in found):
                ambiguous = True
        for target, start, end in found:
            if target in sources:
                reads.setdefault(target, []).append({"file": file, "line": text.count("\n", 0, start) + 1})
                accepted.setdefault(file, []).append((start, end))
    if not ambiguous:
        # Index unexplained references once, rather than scanning the corpus
        # again for every file a repository arranges to read as text.
        unexplained = set()
        for file, text in texts.items():
            intervals = sorted(accepted.get(file, []))
            starts = [start for start, _ in intervals]
            for literal in _STRINGS.finditer(text):
                index = bisect.bisect_right(starts, literal.start()) - 1
                if index >= 0 and literal.start() < intervals[index][1]:
                    continue
                value = _literal(literal.group())
                if value is not None:
                    unexplained.update(
                        ref for ref in (_relative("", value), _relative(posixpath.dirname(file), value)) if ref
                    )
            if Path(file).suffix.lower() in _METADATA:
                for token in _PATH_TOKEN.finditer(text):
                    for ref in (_relative("", token.group()), _relative(posixpath.dirname(file), token.group())):
                        if ref:
                            unexplained.add(ref)
                            # Launchers and module settings can omit suffixes
                            # or use Python's dotted module notation.
                            unexplained.update(
                                candidate for candidate in js_module_candidates(ref) if candidate in sources
                            )
                            stem = ref.replace(".", "/")
                            unexplained.update(
                                candidate
                                for candidate in (ref + ".py", stem + ".py", posixpath.join(stem, "__init__.py"))
                                if candidate in sources
                            )
        for target, evidence in reads.items():
            parts = target.split("/")
            prefixes = {".", *("/".join(parts[:index]) for index in range(1, len(parts) + 1))}
            if not prefixes & unexplained:
                roles[target] = {
                    "kind": "text-data",
                    "reason": "Module-relative text read used only in a JSON response",
                    "evidence": evidence,
                }
    roles.update(runtime)
    return roles


def classify_paths(root: Path, paths: Iterable[Path]) -> dict[str, dict]:
    """Read only caller-selected regular sources, with whole-analysis fallback on limits or unreadable files."""
    sources, complete, used = {}, True, 0
    for number, path in enumerate(paths):
        limit = min(MAX_FILE_BYTES, MAX_BYTES - used)
        if number >= MAX_FILES or limit <= 0:
            complete = False
            break
        if (
            path.is_symlink()
            or any(parent.is_symlink() for parent in path.parents if parent == root or root in parent.parents)
            or not is_safe_to_read(path, root)
        ):
            complete = False
            continue
        try:
            with path.open("rb") as stream:
                content = stream.read(limit + 1)
            used += len(content)
            if len(content) > limit:
                complete = False
                continue
            sources[path.relative_to(root).as_posix()] = content.decode("utf-8")
        except (OSError, UnicodeError, ValueError):
            complete = False
    entries = set()
    manifest = root / "package.json"
    if manifest.is_symlink():
        complete = False
    if is_safe_to_read(manifest, root) and manifest.is_file():
        try:
            with manifest.open("rb") as stream:
                content = stream.read(MAX_FILE_BYTES + 1)
            if len(content) > MAX_FILE_BYTES:
                raise ValueError("manifest limit")
            document = json.loads(content.decode("utf-8"))
            values = [document.get("main"), document.get("module"), document.get("bin"), document.get("exports")]
            visited = 0
            while values:
                visited += 1
                if visited > 8192:
                    complete = False
                    break
                value = values.pop()
                if isinstance(value, dict):
                    values.extend(value.values())
                elif isinstance(value, list):
                    values.extend(value)
                elif isinstance(value, str):
                    if any(char in value for char in "*$`"):
                        complete = False
                    target = _relative("", value)
                    if target:
                        resolved = {candidate for candidate in js_module_candidates(target) if candidate in sources}
                        entries.update(resolved)
                        complete &= bool(resolved)
                    else:
                        complete = False
            for command in document.get("scripts", {}).values():
                if not isinstance(command, str):
                    complete = False
                    continue
                if re.search(r"[^A-Za-z0-9_./:=@+ -]|(?:^|\s)(?:-(?:e|p)\b|--(?:eval|print)\b)", command):
                    complete = False
                for word in re.split(r"[\s=]+", command):
                    target = _relative("", word.strip("'\""))
                    if target:
                        resolved = {candidate for candidate in js_module_candidates(target) if candidate in sources}
                        entries.update(resolved)
                        if Path(target).suffix.lower() in _JS | {".py", ".sh", ".bash", ".ps1"} and not resolved:
                            complete = False
        except (OSError, UnicodeError, ValueError, AttributeError, RecursionError):
            complete = False
    return classify(sources, entries=entries, complete=complete)
