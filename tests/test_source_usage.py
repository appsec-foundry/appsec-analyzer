"""Whole source files used as text must not create server routes (REQ-040)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from analyzers import source_usage as su
from analyzers.route_inventory import build_inventory
from model import case_candidates as cc

JS_SERVER = """import fs from 'node:fs'
import express from 'express'
const app = express()
app.get('/source', (req, res) => {
  const text = fs.readFileSync(new URL('./assets/sample.js', import.meta.url), 'utf8');
  return res.json({source: text})
})
"""
JS_SAMPLE = "app.get('/orders/:id', (req, res) => res.json(db.findById(req.params.id)))\n"
PY_SERVER = """from pathlib import Path
from flask import Flask, jsonify
app = Flask(__name__)
@app.get('/source')
def source():
    text = (Path(__file__).parent / 'assets' / 'sample.py').read_text(encoding='utf-8')
    return jsonify(source=text)
"""
PY_SAMPLE = "@app.get('/orders/<id>')\ndef orders(id):\n    return db.find(id)\n"


def _sources(server=JS_SERVER):
    return {"server.mjs": server, "assets/sample.js": JS_SAMPLE}


def _write(root: Path, sources: dict[str, str]):
    for file, text in sources.items():
        path = root / file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return [root / file for file in sources]


@pytest.mark.parametrize("path", ["assets/sample.js", "src/controllers/orders.js", "any/other/name.js"])
def test_role_follows_text_use_instead_of_directory_names(path):
    server = JS_SERVER.replace("assets/sample.js", path)
    role = su.classify({"server.mjs": server, path: JS_SAMPLE})[path]
    assert role == {
        "kind": "text-data",
        "reason": "Module-relative text read used only in a JSON response",
        "evidence": [{"file": "server.mjs", "line": 5}],
    }


@pytest.mark.parametrize(
    "server",
    [
        JS_SERVER,
        JS_SERVER.replace("import fs from 'node:fs'", "const fs = require('fs')"),
        JS_SERVER.replace("import fs from 'node:fs'", "import fs from 'node:fs/promises'")
        .replace("(req, res) =>", "async (req, res) =>")
        .replace("fs.readFileSync", "await fs.readFile"),
        "import path from 'node:path'\n"
        + JS_SERVER.replace(
            "new URL('./assets/sample.js', import.meta.url)", "path.join(__dirname, 'assets', 'sample.js')"
        ),
    ],
)
def test_recognized_standard_javascript_text_reads(server):
    assert su.classify(_sources(server))["assets/sample.js"]["kind"] == "text-data"


def _with_helper(helper, call="readText('sample.js')"):
    server = JS_SERVER.replace("fs.readFileSync(new URL('./assets/sample.js', import.meta.url), 'utf8')", call)
    return "import path from 'node:path'\n" + server.replace("app.get('/source'", helper + "\napp.get('/source'")


@pytest.mark.parametrize(
    "helper",
    [
        "function readText(name) { return fs.readFileSync(new URL('./assets/' + name, import.meta.url), 'utf8') }",
        "const readText = (name) => fs.readFileSync(new URL(`./assets/${name}`, import.meta.url), 'utf8')",
        "const readText = name => { return fs.readFileSync(path.join(__dirname, 'assets', name), 'utf8') }",
        "function readText(name: string): string { return fs.readFileSync(path.join(__dirname, 'assets', name), 'utf8') }",
    ],
)
def test_local_text_helpers_resolve_literal_arguments_and_composed_paths(helper):
    roles = su.classify(_sources(_with_helper(helper)))
    assert roles["assets/sample.js"]["kind"] == "text-data"
    assert len(roles["assets/sample.js"]["evidence"]) == 2


def test_bounded_helper_chain_keeps_the_read_and_call_evidence():
    helper = "function readText(name) { return fs.readFileSync(new URL('./assets/' + name, import.meta.url), 'utf8') }\nfunction loadExample() { return readText('sample.js') }"
    roles = su.classify(_sources(_with_helper(helper, "loadExample()")))
    assert roles["assets/sample.js"]["kind"] == "text-data"
    assert len(roles["assets/sample.js"]["evidence"]) == 3


@pytest.mark.parametrize("expression", ["'./assets/' + ('sample' + '.js')", "`./assets/${'sample' + '.js'}`"])
def test_constant_composed_paths_are_text_reads(expression):
    server = JS_SERVER.replace("'./assets/sample.js'", expression)
    assert su.classify(_sources(server))["assets/sample.js"]["kind"] == "text-data"


@pytest.mark.parametrize(
    "extra",
    [
        "export { readText }\n",
        "const alias = readText\n",
        "custom(readText)\n",
        "const other = readText('sample.js'); custom(other)\n",
        "function unused(name) { return readText(name) }\n",
        "URL = custom\n",
    ],
)
def test_escaped_helpers_or_unknown_consumers_keep_route_candidates(extra):
    helper = "function readText(name) { return fs.readFileSync(new URL('./assets/' + name, import.meta.url), 'utf8') }"
    roles = su.classify(_sources(_with_helper(helper) + extra))
    assert roles["assets/sample.js"]["kind"] == "unknown"


@pytest.mark.parametrize(
    "call", ["readText(req.query.file)", "readText('../escape.js')", "readText('sample.js', 'extra')", "readText(12)"]
)
def test_unknown_or_invalid_helper_arguments_keep_candidates(call):
    helper = "function readText(name) { return fs.readFileSync(new URL('./assets/' + name, import.meta.url), 'utf8') }"
    assert su.classify(_sources(_with_helper(helper, call)))["assets/sample.js"]["kind"] == "unknown"


@pytest.mark.parametrize(
    "helper",
    [
        "function readText(name) { sideEffect(); return fs.readFileSync(new URL('./assets/' + name, import.meta.url), 'utf8') }",
        "export function readText(name) { return fs.readFileSync(new URL('./assets/' + name, import.meta.url), 'utf8') }",
        "function readText(name) { return\nfs.readFileSync(new URL('./assets/' + name, import.meta.url), 'utf8') }",
    ],
)
def test_helpers_with_untraced_execution_are_unknown(helper):
    assert su.classify(_sources(_with_helper(helper)))["assets/sample.js"]["kind"] == "unknown"


@pytest.mark.parametrize("limit", ["MAX_HELPERS", "MAX_HELPER_DEPTH", "MAX_HELPER_BODY"])
def test_helper_limits_leave_routes_eligible(limit, monkeypatch):
    monkeypatch.setattr(su, limit, 0)
    helper = "function readText(name) { return fs.readFileSync(new URL('./assets/' + name, import.meta.url), 'utf8') }"
    assert su.classify(_sources(_with_helper(helper)))["assets/sample.js"]["kind"] == "unknown"


@pytest.mark.parametrize("argument", ["u'sample.js'", "'''sample.js'''", "'sample' '.js'", r"'\U00000073ample.js'"])
def test_non_javascript_constant_forms_do_not_establish_text_use(argument):
    helper = "function readText(name) { return fs.readFileSync(new URL('./assets/' + name, import.meta.url), 'utf8') }"
    assert su.classify(_sources(_with_helper(helper, f"readText({argument})")))["assets/sample.js"]["kind"] == "unknown"


def test_helper_classification_removes_only_route_candidates(tmp_path):
    helper = "function readText(name) { return fs.readFileSync(new URL('./assets/' + name, import.meta.url), 'utf8') }"
    _write(tmp_path, _sources(_with_helper(helper)))
    (tmp_path / "README.md").write_text("# Example application\n")
    inventory = build_inventory(tmp_path)
    assert {row["path"] for row in inventory["routes"]} == {"/source"}
    findings = [{"file": "assets/sample.js", "line": 1, "check_id": "TEST-1"}]
    facts = cc.route_facts(tmp_path, inventory, findings, components={"api": list(_sources())})
    assert "assets/sample.js" in facts["files"]
    assert "assets/sample.js" in facts["signals"]["database_access"]
    case = {"id": "example", "starting_points": {"rules": ["TEST-1"]}, "applies_when": []}
    assert cc.starting_candidates(case, "api", facts, findings)["candidates"][0]["rule_ids"] == ["TEST-1"]
    (tmp_path / "server.mjs").write_text(_with_helper(helper) + "import './assets/sample.js'\n")
    assert any(row["handler_file"] == "assets/sample.js" for row in build_inventory(tmp_path)["routes"])


def test_text_helpers_keep_many_source_files_without_planning_their_example_routes(tmp_path):
    calls = "\n".join(f"  const example{i} = readText('item-{i}.js');" for i in range(24))
    output = ", ".join(f"example{i}" for i in range(24))
    server = (
        "import fs from 'node:fs'\nimport express from 'express'\nconst app = express()\n"
        "function readText(name) { return fs.readFileSync(new URL('./assets/' + name, import.meta.url), 'utf8') }\n"
        "app.get('/source', (req,res) => {\n" + calls + "\n  return res.json({" + output + "})\n})\n"
    )
    files = {
        "server.mjs": server,
        **{
            f"assets/item-{i}.js": "\n".join(f"app.get('/example-{i}-{j}/:id', handler)" for j in range(3))
            for i in range(24)
        },
    }
    _write(tmp_path, files)
    inventory = build_inventory(tmp_path)
    assert len(inventory["routes"]) == 1
    facts = cc.route_facts(tmp_path, inventory, [], components={"api": list(files)})
    from model.case_outcomes import load_catalog

    case = next(
        case
        for case in load_catalog()["test_cases"]
        if "route_inventory.authn_signal" in case["starting_points"].get("facts", [])
    )
    candidates = cc.starting_candidates(case, "api", facts, [])["candidates"]
    assert len(candidates) == len(cc.batches({case["id"]: candidates}, facts=facts)) == 1
    assert set(files) <= set(facts["files"])


@pytest.mark.parametrize(
    "extra",
    [
        "import './assets/sample.js'\n",
        "import handler from './assets/sample.js'\n",
        "const handler = require('./assets/sample.js')\n",
        "export * from './assets/sample.js'\n",
    ],
)
def test_module_reference_takes_precedence_over_text_use(extra):
    roles = su.classify(_sources(JS_SERVER + extra))
    assert roles["assets/sample.js"]["kind"] == "runtime"


@pytest.mark.parametrize(
    "replacement",
    [
        "return res.json({source: eval(text)})",
        "custom(text)\n  return res.json({source: text})",
        "return res.json({source: compile(text)})",
        "return res.send(text)",
        "modify(res)\n  return res.json({source: text})",
        "res.json = execute\n  return res.json({source: text})",
        "return res.json({...text})",
    ],
)
def test_text_used_outside_plain_json_is_unknown(replacement):
    server = JS_SERVER.replace("return res.json({source: text})", replacement)
    assert su.classify(_sources(server))["assets/sample.js"]["kind"] == "unknown"


@pytest.mark.parametrize(
    "extra",
    [
        "const load = require(name)\n",
        "import(name)\n",
        "const routes = import.meta.glob('./assets/*.js')\n",
        "require.context('./assets', true)\n",
        "process.chdir(folder)\n",
        "const extra = fs.readFileSync(name, 'utf8')\n",
        "const run = fs.readFileSync(new URL('./assets/sample.js', import.meta.url), 'utf8'); eval(run)\n",
        "install(app)\n",
        "app.use(custom)\n",
        "const URL = custom\n",
        "fs.readFileSync = custom\n",
    ],
)
def test_ambiguous_loading_or_bindings_keep_candidate(extra):
    assert su.classify(_sources(JS_SERVER + extra))["assets/sample.js"]["kind"] == "unknown"


@pytest.mark.parametrize(
    "expression",
    [
        "'./assets/sample.js'",
        "variable",
        "new URL('../sample.js', import.meta.url)",
        "new URL('./assets/sample%2ejs', import.meta.url)",
    ],
)
def test_unresolved_or_cwd_relative_paths_keep_candidate(expression):
    server = JS_SERVER.replace("new URL('./assets/sample.js', import.meta.url)", expression)
    assert su.classify(_sources(server))["assets/sample.js"]["kind"] == "unknown"


def test_python_text_use_and_runtime_import():
    sources = {"server.py": PY_SERVER, "assets/sample.py": PY_SAMPLE}
    assert su.classify(sources)["assets/sample.py"]["kind"] == "text-data"
    sources["server.py"] += "from assets import sample\n"
    assert su.classify(sources)["assets/sample.py"]["kind"] != "text-data"


@pytest.mark.parametrize(
    "change",
    [
        "    execute(text)\n    return jsonify(source=text)",
        "    return jsonify(source=eval(text))",
        "    return text",
        "    jsonify = execute\n    return jsonify(source=text)",
        "    return jsonify(**text)",
    ],
)
def test_python_unknown_text_destinations_and_shadowing(change):
    server = PY_SERVER.replace("    return jsonify(source=text)", change)
    assert su.classify({"server.py": server, "assets/sample.py": PY_SAMPLE})["assets/sample.py"]["kind"] == "unknown"


def test_python_module_relative_with_name_and_unicode_offsets():
    server = PY_SERVER.replace(
        "Path(__file__).parent / 'assets' / 'sample.py'", "Path(__file__).with_name('sample.py')"
    )
    server = server.replace("    text =", "    label = 'Grüße'; text =")
    assert su.classify({"server.py": server, "sample.py": PY_SAMPLE})["sample.py"]["kind"] == "text-data"


@pytest.mark.parametrize("extra", [{"loader.go": "package main"}, {"broken.py": "def ("}])
def test_unsupported_or_invalid_source_keeps_unknown(extra):
    assert su.classify({**_sources(), **extra})["assets/sample.js"]["kind"] == "unknown"


def test_limits_and_incomplete_corpus_keep_unknown(monkeypatch):
    assert su.classify(_sources(), complete=False)["assets/sample.js"]["kind"] == "unknown"
    assert su.classify(_sources(), entries=["assets/sample.js"])["assets/sample.js"]["kind"] == "runtime"
    monkeypatch.setattr(su, "MAX_BYTES", 10)
    assert su.classify(_sources())["assets/sample.js"]["kind"] == "unknown"


@pytest.mark.parametrize("field", ["main", "module", "bin", "exports"])
def test_package_entries_override_text_use(tmp_path, field):
    paths = _write(tmp_path, _sources())
    (tmp_path / "package.json").write_text(json.dumps({field: "./assets/sample.js"}))
    assert su.classify_paths(tmp_path, paths)["assets/sample.js"]["kind"] == "runtime"


def test_package_script_entry_and_dynamic_command(tmp_path):
    paths = _write(tmp_path, _sources())
    manifest = tmp_path / "package.json"
    manifest.write_text(json.dumps({"scripts": {"start": "node assets/sample.js"}}))
    assert su.classify_paths(tmp_path, paths)["assets/sample.js"]["kind"] == "runtime"
    manifest.write_text(json.dumps({"scripts": {"start": "node $ENTRY"}}))
    assert su.classify_paths(tmp_path, paths)["assets/sample.js"]["kind"] == "unknown"
    manifest.write_text("{")
    assert su.classify_paths(tmp_path, paths)["assets/sample.js"]["kind"] == "unknown"


def test_unreadable_symlink_or_limit_never_establishes_text_only(tmp_path, monkeypatch):
    paths = _write(tmp_path, _sources())
    (tmp_path / "alias.js").symlink_to(tmp_path / "assets/sample.js")
    assert su.classify_paths(tmp_path, [*paths, tmp_path / "alias.js"])["assets/sample.js"]["kind"] == "unknown"
    assert su.classify_paths(tmp_path, [*paths, tmp_path / "missing.js"])["assets/sample.js"]["kind"] == "unknown"
    monkeypatch.setattr(su, "MAX_FILE_BYTES", 10)
    assert all(role["kind"] != "text-data" for role in su.classify_paths(tmp_path, paths).values())


def test_inventory_and_verification_drop_false_routes_but_retain_other_analysis(tmp_path):
    _write(tmp_path, _sources())
    inventory = build_inventory(tmp_path)
    assert {(row["handler_file"], row["path"]) for row in inventory["routes"]} == {("server.mjs", "/source")}
    # Old or separately produced inventories must receive the same correction.
    stale = {
        **inventory["routes"][0],
        "route_id": "R-900",
        "handler_file": "assets/sample.js",
        "handler_line": 1,
        "path": "/orders/:id",
    }
    findings = [{"file": "assets/sample.js", "line": 1, "check_id": "TEST-1"}]
    facts = cc.route_facts(tmp_path, [*inventory["routes"], stale], findings, components={"api": list(_sources())})
    assert "assets/sample.js" in facts["files"]
    assert "R-900" not in facts["routes"]
    # The database access remains a code signal; text classification is not
    # a file-admission or scanner-hit exclusion.
    assert "assets/sample.js" in facts["signals"]["database_access"]
    case = {"id": "test-case", "starting_points": {"rules": ["TEST-1"]}, "applies_when": []}
    candidates = cc.starting_candidates(case, "api", facts, findings)["candidates"]
    assert [candidate["anchor"] for candidate in candidates] == [{"file": "assets/sample.js", "line": 1}]
    (tmp_path / "server.mjs").write_text(JS_SERVER + "import './assets/sample.js'\n")
    inventory = build_inventory(tmp_path)
    assert any(row["handler_file"] == "assets/sample.js" for row in inventory["routes"])


def test_generated_routes_in_a_text_file_are_not_reintroduced(tmp_path):
    source = "import finale from 'finale-rest'\nfinale.resource({ model: User, endpoints: ['/users', '/users/:id'] })\n"
    _write(tmp_path, {**_sources(), "assets/sample.js": source})
    facts = cc.route_facts(tmp_path, [], [])
    assert "assets/sample.js" in facts["files"]
    assert not facts["routes"]


@pytest.mark.parametrize(
    "metadata,content",
    [
        ("README.md", "# Project\n\nExamples are returned as JSON.\n"),
        ("package.json", '{"name":"example","dependencies":{"express":"*"}}'),
        ("config.yaml", "service: example\n"),
        ("config.toml", 'title = "example"\n'),
    ],
)
def test_metadata_does_not_resurrect_routes_from_a_text_file(tmp_path, metadata, content):
    source = "import finale from 'finale-rest'\nfinale.resource({ model: User, endpoints: ['/users', '/users/:id'] })\n"
    sources = {**_sources(), "assets/sample.js": source, metadata: content}
    paths = _write(tmp_path, sources)
    usage = su.classify_paths(tmp_path, paths)
    assert usage["assets/sample.js"]["kind"] == "text-data"
    inventory = build_inventory(tmp_path)
    facts = cc.route_facts(tmp_path, inventory, [])
    assert {(row["handler_file"], row["path"]) for row in facts["routes"].values()} == {("server.mjs", "/source")}
    assert set(sources) <= set(facts["files"])


@pytest.mark.parametrize(
    "metadata,content",
    [
        ("config.yaml", "command: node assets/sample.js\n"),
        ("config.toml", 'command = "node assets/sample.js"\n'),
        ("config.json", '{"command":"node assets/sample.js"}'),
        ("README.md", "Run `node assets/sample.js` to start the example.\n"),
        ("config.yaml", "command: node $ENTRY\n"),
        ("config.json", '{"scripts":{"start":"node $ENTRY"}}'),
        ("config.yaml", "steps:\n  - run: node $ENTRY\n"),
        ("config.yaml", "command: node --require ./assets/sample\n"),
        ("config.toml", '[project.scripts]\nserve = "assets.sample:main"\n'),
        ("config.yaml", "command: node /application/assets/sample.js\n"),
        ("config.json", '{"command":"custom-loader"}'),
    ],
)
def test_metadata_loading_references_still_keep_route_candidates(metadata, content):
    roles = su.classify({**_sources(), metadata: content})
    assert roles["assets/sample.js"]["kind"] == "unknown"


@pytest.mark.parametrize("loader", ["README.md", "loader.txt", "config.json"])
def test_metadata_names_do_not_hide_declared_or_imported_programs(loader):
    sources = {**_sources(), loader: "custom_loader(variable)\n"}
    assert su.classify(sources, entries=[loader])["assets/sample.js"]["kind"] == "unknown"
    sources["server.mjs"] += f"import './{loader}'\n"
    assert su.classify(sources)["assets/sample.js"]["kind"] == "unknown"


def test_a_shebang_in_a_document_keeps_execution_uncertain():
    roles = su.classify({**_sources(), "loader.txt": '#!/bin/sh\nnode "$ENTRY"\n'})
    assert roles["assets/sample.js"]["kind"] == "unknown"


def test_metadata_python_module_launch_keeps_the_program_candidate():
    sources = {
        "server.py": PY_SERVER,
        "assets/sample.py": PY_SAMPLE,
        "config.yaml": "command: python -m assets.sample\n",
    }
    assert su.classify(sources)["assets/sample.py"]["kind"] == "unknown"


def test_long_metadata_whitespace_does_not_invalidate_text_use():
    sources = {**_sources(), "config.toml": "\n" * 12000 + 'service = "example"\n'}
    assert su.classify(sources)["assets/sample.js"]["kind"] == "text-data"


@pytest.mark.parametrize(
    "loader",
    [
        "const load = require; load(name)\n",
        "const {readFileSync} = require('fs'); readFileSync(name, 'utf8')\n",
        "import cp from 'child_process'; cp.spawn(command, arguments)\n",
        "eval(source)\n",
    ],
)
def test_uncertain_loader_in_another_file_keeps_candidate(loader):
    assert su.classify({**_sources(), "loader.js": loader})["assets/sample.js"]["kind"] == "unknown"


@pytest.mark.parametrize(
    "change",
    [
        "app.json = custom",
        "configure(jsonify)",
        "configure(Path)",
        "app.before_request(custom)",
    ],
)
def test_python_modified_response_or_reader_keeps_unknown(change):
    roles = su.classify({"server.py": PY_SERVER + change + "\n", "assets/sample.py": PY_SAMPLE})
    assert roles["assets/sample.py"]["kind"] == "unknown"


@pytest.mark.parametrize("limit", ["MAX_FILES", "MAX_READS", "MAX_PYTHON_NODES"])
def test_analysis_limits_keep_candidates(limit, monkeypatch):
    monkeypatch.setattr(su, limit, 0)
    sources = {"server.py": PY_SERVER, "assets/sample.py": PY_SAMPLE} if limit == "MAX_PYTHON_NODES" else _sources()
    assert all(role["kind"] != "text-data" for role in su.classify(sources).values())


def test_escaping_source_link_is_never_read(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    paths = _write(root, _sources())
    outside = tmp_path / "outside.js"
    outside.write_text('app.get("/outside", handler)')
    link = root / "linked.js"
    link.symlink_to(outside)
    open_file = Path.open

    def guarded_open(path, *args, **kwargs):
        assert path not in {link, outside}
        return open_file(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    assert su.classify_paths(root, [*paths, link])["assets/sample.js"]["kind"] == "unknown"


def test_package_extensionless_entry_and_dynamic_exports(tmp_path):
    paths = _write(tmp_path, _sources())
    manifest = tmp_path / "package.json"
    manifest.write_text(json.dumps({"main": "./assets/sample"}))
    assert su.classify_paths(tmp_path, paths)["assets/sample.js"]["kind"] == "runtime"
    manifest.write_text(json.dumps({"exports": {"./*": "./assets/*.js"}}))
    assert su.classify_paths(tmp_path, paths)["assets/sample.js"]["kind"] == "unknown"


def test_flask_route_extraction_has_the_same_text_file_rule(tmp_path):
    _write(tmp_path, {"server.py": PY_SERVER, "assets/sample.py": PY_SAMPLE})
    assert {(row["handler_file"], row["path"]) for row in build_inventory(tmp_path)["routes"]} == {
        ("server.py", "/source")
    }


def test_python_parent_path_cannot_clamp_an_escape_to_the_repository():
    server = PY_SERVER.replace("Path(__file__).parent / 'assets'", "Path(__file__).parent.parent / 'assets'")
    assert su.classify({"server.py": server, "assets/sample.py": PY_SAMPLE})["assets/sample.py"]["kind"] == "unknown"


def test_linked_parent_directory_leaves_source_use_unknown(tmp_path):
    paths = _write(tmp_path, _sources())
    (tmp_path / "alias").symlink_to(tmp_path / "assets", target_is_directory=True)
    roles = su.classify_paths(tmp_path, [*paths, tmp_path / "alias/sample.js"])
    assert roles["assets/sample.js"]["kind"] == "unknown"


def test_quoted_import_does_not_establish_a_standard_framework_binding():
    server = JS_SERVER.replace("import express from 'express'", '''const example = "import express from 'express'"''')
    assert su.classify(_sources(server))["assets/sample.js"]["kind"] == "unknown"


@pytest.mark.parametrize("shadow", ["flask.py", "pathlib.py"])
def test_local_python_modules_cannot_establish_standard_text_use(shadow):
    sources = {"server.py": PY_SERVER, "assets/sample.py": PY_SAMPLE, shadow: "def custom(value): return value\n"}
    assert su.classify(sources)["assets/sample.py"]["kind"] == "unknown"


@pytest.mark.parametrize(
    "manifest",
    [
        {"main": "./not-admitted.js"},
        {"scripts": {"start": 'node --eval "require(process.env.ENTRY)"'}},
        {"scripts": {"start": "bash loader.sh"}},
    ],
)
def test_unresolved_package_launchers_keep_candidates(tmp_path, manifest):
    paths = _write(tmp_path, _sources())
    (tmp_path / "package.json").write_text(json.dumps(manifest))
    assert su.classify_paths(tmp_path, paths)["assets/sample.js"]["kind"] == "unknown"


def test_package_preload_argument_is_a_runtime_reference(tmp_path):
    paths = _write(tmp_path, _sources())
    (tmp_path / "package.json").write_text(
        json.dumps({"scripts": {"start": "node --require=./assets/sample.js server.mjs"}})
    )
    assert su.classify_paths(tmp_path, paths)["assets/sample.js"]["kind"] == "runtime"


def test_failed_reads_count_toward_the_file_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(su, "MAX_FILES", 2)

    def selected():
        yield tmp_path / "missing-1.js"
        yield tmp_path / "missing-2.js"
        yield tmp_path / "missing-3.js"
        raise AssertionError("continued beyond the file limit")

    assert su.classify_paths(tmp_path, selected()) == {}


def test_actual_io_uses_a_byte_limit(tmp_path, monkeypatch):
    paths = _write(tmp_path, _sources())
    monkeypatch.setattr(su, "MAX_BYTES", 10)
    monkeypatch.setattr(su, "MAX_FILE_BYTES", 10)
    calls = []
    open_file = Path.open

    class Limited:
        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

        def read(self, size):
            calls.append(size)
            return b"x" * size

    def guarded_open(path, *args, **kwargs):
        return Limited() if path in paths else open_file(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)
    assert su.classify_paths(tmp_path, paths) == {}
    assert calls == [11]
