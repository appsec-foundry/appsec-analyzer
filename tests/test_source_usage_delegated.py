"""Delegated text reads retain every source and every uncertain route (REQ-040)."""

import pytest
from analyzers import source_usage as su

SAMPLE = "app.get('/orders/:id', (req, res) => res.json(db.findById(req.params.id)))\n"
READ = "fs.readFileSync(new URL('./assets/sample.js', import.meta.url), 'utf8')"
SERVER = """import express from 'express'
import { readExample } from './reader.mjs'
const app = express()
app.get('/source', (req, res) => {
  const value = readExample();
  return res.json({source: value})
})
"""
READER = "import fs from 'node:fs'\nexport function readExample () {\n  return " + READ + "\n}\n"
CACHED = (
    "import fs from 'node:fs'\nlet cached = null\nexport function readExample () {\n  if (cached === null) {\n    cached = "
    + READ
    + "\n  }\n  return cached\n}\n"
)
DIRECTORY = "import fs from 'node:fs'\nexport function readExample () {\n  return fs.readdirSync(new URL('./assets/', import.meta.url)).map(name => fs.readFileSync(new URL('./assets/' + name, import.meta.url), 'utf8'))\n}\n"


def sources(reader=READER, server=SERVER):
    return {"server.mjs": server, "reader.mjs": reader, "assets/sample.js": SAMPLE}


@pytest.mark.parametrize(
    "reader", [READER, CACHED, DIRECTORY, CACHED.replace(READ, DIRECTORY.split("  return ")[1].split("\n}")[0])]
)
def test_fixed_delegated_text_is_recognized(reader):
    assert su.classify(sources(reader))["assets/sample.js"]["kind"] == "text-data"


@pytest.mark.parametrize("reader", [READER, CACHED, DIRECTORY])
def test_literal_import_alias_is_traced(reader):
    server = SERVER.replace("{ readExample }", "{ readExample as sourceText }").replace(
        "= readExample()", "= sourceText()"
    )
    assert su.classify(sources(reader, server))["assets/sample.js"]["kind"] == "text-data"


@pytest.mark.parametrize("reader", [READER, CACHED, DIRECTORY])
@pytest.mark.parametrize(
    "extra",
    [
        "import './assets/sample.js'\n",
        "export * from './assets/sample.js'\n",
    ],
)
def test_executable_reference_still_wins(reader, extra):
    assert su.classify(sources(reader, SERVER + extra))["assets/sample.js"]["kind"] == "runtime"


@pytest.mark.parametrize(
    "extra",
    [
        "const load = require; load(name)\n",
        "const {readFileSync} = require('fs'); readFileSync(name, 'utf8')\n",
        "import cp from 'child_process'; cp.spawn(command, arguments)\n",
        "eval(source)\n",
        "import(name)\n",
        "require('./' + name)\n",
        "import('./reader.mjs' + suffix)\n",
        "process.chdir(folder)\n",
    ],
)
def test_unknown_loader_in_another_file_stays_global(extra):
    data = {**sources(CACHED), "loader.mjs": extra}
    assert su.classify(data)["assets/sample.js"]["kind"] == "unknown"


@pytest.mark.parametrize(
    "extra",
    [
        "consume(readExample)\n",
        "const escaped = readExample\n",
        "export { readExample }\n",
        "readExample = custom\n",
        "const extra = readExample(); consume(extra)\n",
        "import * as escaped from './reader.mjs'; consume(escaped)\n",
        "const escaped = require('./reader.mjs'); consume(escaped)\n",
        "import './reader.mjs'\n",
    ],
)
def test_additional_consumer_or_module_escape_keeps_candidate(extra):
    assert su.classify(sources(CACHED, SERVER + extra))["assets/sample.js"]["kind"] == "unknown"


@pytest.mark.parametrize(
    "extra",
    [
        "consume(cached)\n",
        "export { cached }\n",
        "cached = attacker\n",
        "cached += attacker\n",
    ],
)
def test_cache_escape_or_write_keeps_candidate(extra):
    assert su.classify(sources(CACHED + extra))["assets/sample.js"]["kind"] == "unknown"


@pytest.mark.parametrize(
    "replacement",
    [
        "return res.json({source: eval(value)})",
        "consume(value); return res.json({source: value})",
        "return res.send(value)",
        "res.json = execute; return res.json({source: value})",
        "return res.json({...value})",
    ],
)
def test_non_json_consumer_keeps_candidate(replacement):
    server = SERVER.replace("return res.json({source: value})", replacement)
    assert su.classify(sources(CACHED, server))["assets/sample.js"]["kind"] == "unknown"


@pytest.mark.parametrize(
    "expression",
    [
        "fs.readFileSync('./assets/sample.js', 'utf8')",
        "fs.readFileSync(name, 'utf8')",
        "fs.readFileSync(new URL('./assets/sample.js', import.meta.url), 'latin1')",
        "custom()",
    ],
)
def test_unresolved_reader_keeps_candidate(expression):
    assert su.classify(sources(CACHED.replace(READ, expression)))["assets/sample.js"]["kind"] == "unknown"


def test_incomplete_corpus_keeps_candidate():
    assert su.classify(sources(CACHED), complete=False)["assets/sample.js"]["kind"] == "unknown"


def test_exporting_entry_keeps_candidate():
    assert su.classify(sources(CACHED), entries=["reader.mjs"])["assets/sample.js"]["kind"] == "unknown"


def test_declared_target_entry_wins():
    assert su.classify(sources(CACHED), entries=["assets/sample.js"])["assets/sample.js"]["kind"] == "runtime"


@pytest.mark.parametrize(
    "extra",
    [
        "Array.prototype.map = execute\n",
        "Object.defineProperty(Array.prototype, 'map', descriptor)\n",
        "const list = []; list.__proto__.map = execute\n",
        "const list = []; list['__proto__'].map = execute\n",
        "const list = []; list[key] = execute\n",
    ],
)
def test_customized_directory_mapping_keeps_candidate(extra):
    assert su.classify({**sources(DIRECTORY), "custom.mjs": extra})["assets/sample.js"]["kind"] == "unknown"


def test_directory_limit_keeps_candidate():
    data = sources(DIRECTORY)
    data.update({f"assets/file-{number}.js": SAMPLE for number in range(su.MAX_READS)})
    assert su.classify(data)["assets/sample.js"]["kind"] == "unknown"


def test_proof_limit_keeps_candidate(monkeypatch):
    monkeypatch.setattr(su, "MAX_DELEGATED_HELPERS", 0)
    assert su.classify(sources(CACHED))["assets/sample.js"]["kind"] == "unknown"


def test_declared_entries_generator_is_retained():
    entries = (file for file in ["assets/sample.js"])
    assert su.classify(sources(CACHED), entries=entries)["assets/sample.js"]["kind"] == "runtime"


def test_cache_declaration_inside_a_string_is_not_a_binding():
    reader = CACHED.replace("let cached = null\n", "const fake = `\nlet cached = null\n`\n")
    assert su.classify(sources(reader))["assets/sample.js"]["kind"] == "unknown"


def test_unknown_consumer_in_another_importer_keeps_candidate():
    other = "import { readExample } from './reader.mjs'\nconst value = readExample(); consume(value)\n"
    assert su.classify({**sources(CACHED), "other.mjs": other})["assets/sample.js"]["kind"] == "unknown"


def test_an_unsupported_import_form_in_another_file_keeps_candidate():
    other = "import * as module from './reader.mjs'\nmodule.readExample()\n"
    assert su.classify({**sources(CACHED), "other.mjs": other})["assets/sample.js"]["kind"] == "unknown"


def test_unsupported_named_import_specifier_keeps_candidate():
    other = "import { 'readExample' as escaped } from './reader.mjs'\nconsume(escaped())\n"
    assert su.classify({**sources(CACHED), "other.mjs": other})["assets/sample.js"]["kind"] == "unknown"


@pytest.mark.parametrize("limit,value", [("MAX_FILES", 2), ("MAX_BYTES", 10), ("MAX_FILE_BYTES", 10)])
def test_source_bounds_are_applied_before_proving(limit, value, monkeypatch):
    monkeypatch.setattr(su, limit, value)

    def unexpected_proof(*args, **kwargs):
        raise AssertionError("Delegated reads must not run after the source limit")

    monkeypatch.setattr(su, "_js_delegated_reads", unexpected_proof)
    assert su.classify(sources(CACHED))["assets/sample.js"]["kind"] == "unknown"


@pytest.mark.parametrize("name", ["fs", "path", "URL", "__dirname"])
def test_directory_callback_cannot_shadow_standard_bindings(name):
    reader = DIRECTORY.replace("name =>", f"{name} =>").replace("+ name,", f"+ {name},")
    if name == "path":
        reader = "import path from 'node:path'\n" + reader
    assert su.classify(sources(reader))["assets/sample.js"]["kind"] == "unknown"


def test_cache_evidence_names_the_read_and_the_json_consumer():
    role = su.classify(sources(CACHED))["assets/sample.js"]
    assert role["kind"] == "text-data"
    assert len(role["evidence"]) == 2
    assert {(row["file"], row["line"]) for row in role["evidence"]} == {("reader.mjs", 5), ("server.mjs", 5)}


@pytest.mark.parametrize("extra_reads,expected", [(su.MAX_READS - 1, "text-data"), (su.MAX_READS, "unknown")])
def test_delegated_bodies_do_not_hide_reads_from_the_file_limit(extra_reads, expected):
    calls = "\n".join(
        f"  const v{index} = fs.readFileSync(new URL('./assets/extra-{index}.js', import.meta.url), 'utf8');"
        for index in range(extra_reads)
    )
    output = ",".join(f"v{index}" for index in range(extra_reads))
    reader = (
        CACHED
        + "import express from 'express'\nconst app = express()\napp.get('/extra', (req, res) => {\n"
        + calls
        + "\n  return res.json({"
        + output
        + "})\n})\n"
    )
    data = sources(reader)
    data.update({f"assets/extra-{index}.js": SAMPLE for index in range(extra_reads)})
    assert su.classify(data)["assets/sample.js"]["kind"] == expected


def test_parallel_classification_keeps_proofs_local():
    from concurrent.futures import ThreadPoolExecutor

    text_sources = sources(CACHED)
    executable = {**text_sources, "loader.mjs": "eval(source)\n"}
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(su.classify, [text_sources, executable] * 4))
    assert [result["assets/sample.js"]["kind"] for result in results] == ["text-data", "unknown"] * 4


@pytest.mark.parametrize("alias", ["$escaped", "escaped$", "left$right"])
def test_dollar_import_names_keep_unknown_consumers(alias):
    other = f"import {{ readExample as {alias} }} from './reader.mjs'\nconsume({alias}())\n"
    assert su.classify({**sources(CACHED), "other.mjs": other})["assets/sample.js"]["kind"] == "unknown"


@pytest.mark.parametrize("name", ["$cached", "cached$", "left$right"])
def test_dollar_cache_names_cannot_escape(name):
    reader = CACHED.replace("cached", name) + f"\nconsume({name})\n"
    assert su.classify(sources(reader))["assets/sample.js"]["kind"] == "unknown"


@pytest.mark.parametrize("name", ["$readExample", "readExample$", "left$right"])
def test_dollar_helper_names_cannot_escape(name):
    reader = READER.replace("readExample", name) + f"\nconsume({name})\n"
    server = SERVER.replace("{ readExample }", f"{{ {name} as readExample }}")
    assert su.classify(sources(reader, server))["assets/sample.js"]["kind"] == "unknown"


@pytest.mark.parametrize("alias", ["$sourceText", "sourceText$", "left$right"])
def test_dollar_import_names_still_trace_known_json_use(alias):
    server = SERVER.replace("{ readExample }", f"{{ readExample as {alias} }}").replace(
        "= readExample()", f"= {alias}()"
    )
    assert su.classify(sources(CACHED, server))["assets/sample.js"]["kind"] == "text-data"


@pytest.mark.parametrize(
    "other",
    [
        "import { readExample } from './reader.mjs'\nconsume(read\\u0045xample())\n",
        "consume('./reader.mjs')\n",
        "import('./read\\u0065r.mjs').then(consume)\n",
        "consume('./read\\u{65}r.mjs')\n",
        "consume(`./reader.mjs`)\n",
        "import { readExample } from './reader.mjs'\nconsume(`${readExample()}`)\n",
        "import { readExample } from './reader.mjs'\nconsume(`${read\\u0045xample()}`)\n",
    ],
)
def test_encoded_or_indirect_module_consumers_keep_candidates(other):
    assert su.classify({**sources(CACHED), "other.mjs": other})["assets/sample.js"]["kind"] == "unknown"


def test_encoded_cache_reference_cannot_escape():
    reader = CACHED + "\nconsume(cach\\u0065d)\n"
    assert su.classify(sources(reader))["assets/sample.js"]["kind"] == "unknown"


def test_unicode_escape_in_plain_json_text_is_not_a_loader():
    server = SERVER.replace("source: value", "source: value, label: '\\u0041'")
    assert su.classify(sources(CACHED, server))["assets/sample.js"]["kind"] == "text-data"


def test_encoded_export_also_keeps_a_private_helper_candidate():
    server = SERVER.replace("import { readExample } from './reader.mjs'", "import fs from 'node:fs'")
    server += READER.split("\n", 1)[1].replace("export function", "function")
    server += "export { read\\u0045xample }\n"
    data = {"server.mjs": server, "assets/sample.js": SAMPLE}
    assert su.classify(data)["assets/sample.js"]["kind"] == "unknown"


def test_template_execution_also_keeps_a_private_helper_candidate():
    server = SERVER.replace("import { readExample } from './reader.mjs'", "import fs from 'node:fs'")
    server += READER.split("\n", 1)[1].replace("export function", "function")
    server += "consume(`${readExample()}`)\n"
    data = {"server.mjs": server, "assets/sample.js": SAMPLE}
    assert su.classify(data)["assets/sample.js"]["kind"] == "unknown"


@pytest.mark.parametrize("reference", ["'reader.mjs'", "`./reader.mjs`", "`reader.mjs`"])
def test_indirect_module_reference_beside_a_named_import_keeps_candidate(reference):
    server = SERVER + f"\nconsume({reference})\n"
    assert su.classify(sources(CACHED, server))["assets/sample.js"]["kind"] == "unknown"


@pytest.mark.parametrize("binding", ["helper", "import_alias"])
def test_long_binding_names_retain_candidates(binding):
    name = "r" * (su.MAX_HELPER_BODY + 1)
    if binding == "helper":
        reader = READER.replace("readExample", name)
        server = SERVER.replace("{ readExample }", f"{{ {name} as readExample }}")
    else:
        reader = CACHED
        server = SERVER.replace("{ readExample }", f"{{ readExample as {name} }}").replace(
            "= readExample()", f"= {name}()"
        )
    assert su.classify(sources(reader, server))["assets/sample.js"]["kind"] == "unknown"


@pytest.mark.parametrize("additional,expected", [(su.MAX_READS - 1, "text-data"), (su.MAX_READS, "unknown")])
def test_import_bindings_are_bounded_even_when_unused(additional, expected):
    data = sources(CACHED)
    data.update(
        {
            f"consumer-{index}.mjs": f"import {{ readExample as unused{index} }} from './reader.mjs'\n"
            for index in range(additional)
        }
    )
    assert su.classify(data)["assets/sample.js"]["kind"] == expected


def _write(root, data):
    for file, text in data.items():
        path = root / file
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


@pytest.mark.parametrize("reader", [CACHED, DIRECTORY])
def test_delegated_reads_preserve_scanner_sites_and_all_sources(tmp_path, reader):
    from analyzers.route_inventory import build_inventory
    from model import case_candidates as cc

    data = sources(reader)
    _write(tmp_path, data)
    inventory = build_inventory(tmp_path)
    assert {row["path"] for row in inventory["routes"]} == {"/source"}
    findings = [{"file": "assets/sample.js", "line": 1, "check_id": "TEST-1"}]
    facts = cc.route_facts(tmp_path, inventory, findings, components={"api": list(data)})
    assert set(data) <= set(facts["files"])
    assert "assets/sample.js" in facts["signals"]["database_access"]
    case = {"id": "example", "starting_points": {"rules": ["TEST-1"]}, "applies_when": []}
    candidate = cc.starting_candidates(case, "api", facts, findings)["candidates"][0]
    assert candidate["rule_ids"] == ["TEST-1"]


def test_directory_examples_reduce_jobs_and_imported_programs_remain(tmp_path):
    from analyzers.route_inventory import build_inventory
    from model import case_candidates as cc
    from model.case_outcomes import load_catalog

    data = {"server.mjs": SERVER, "reader.mjs": DIRECTORY}
    data.update(
        {
            f"assets/item-{i}.js": "\n".join(f"app.get('/example-{i}-{j}/:id', handler)" for j in range(3))
            for i in range(24)
        }
    )
    _write(tmp_path, data)
    case = next(
        case
        for case in load_catalog()["test_cases"]
        if "route_inventory.authn_signal" in case["starting_points"].get("facts", [])
    )

    def measure():
        inventory = build_inventory(tmp_path)
        facts = cc.route_facts(tmp_path, inventory, [], components={"api": list(data)})
        candidates = cc.starting_candidates(case, "api", facts, [])["candidates"]
        return {
            "routes": len(inventory["routes"]),
            "sources": len(facts["files"]),
            "candidates": len(candidates),
            "jobs": len(cc.batches({case["id"]: candidates}, facts=facts)),
        }

    assert measure() == {"routes": 1, "sources": 26, "candidates": 1, "jobs": 1}
    imports = "\n".join(f"import './assets/item-{number}.js'" for number in range(24))
    (tmp_path / "server.mjs").write_text(SERVER + imports, encoding="utf-8")
    assert measure() == {"routes": 73, "sources": 26, "candidates": 73, "jobs": 2}
