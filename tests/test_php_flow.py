"""Bounded request-input flow into PHP SQL and shell calls (scripts/analyzers/php_flow.py)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))
from analyzers import php_flow as P  # noqa: E402


def _sinks(code: str) -> list[tuple[str, int]]:
    return [(h.sink, h.line) for h in P.scan("<?php\n" + code)]


def _kinds(code: str) -> set[str]:
    return {sink for sink, _ in _sinks(code)}


# --- SQL ---------------------------------------------------------------------

SQL_FLOWS = {
    "assigned, then interpolated in quotes": "$id = $_GET['id'];\n$q = \"SELECT * FROM t WHERE id = '$id'\";\nmysqli_query($c, $q);",
    "escaped, but outside quotes": "$id = mysqli_real_escape_string($c, $_POST['id']);\nmysqli_query($c, \"SELECT * FROM t WHERE id = $id\");",
    "tainted on one branch": "if (isset($_GET['s'])) { $s = $_GET['s']; } else { $s = 'name'; }\n$pdo->query('SELECT * FROM t ORDER BY ' . $s);",
    "JSON request body": "$d = json_decode(file_get_contents('php://input'));\n$db->query(\"UPDATE t SET a = '\" . $d->a . \"'\");",
    "Laravel request into DB::select": "function show(Request $request) {\n  return DB::select(\"SELECT * FROM u WHERE n = '\" . $request->input('n') . \"'\");\n}",
    "Laravel magic property into whereRaw": "User::whereRaw(\"email = '{$request->email}'\")->get();",
    "Symfony query bag into DBAL": "$conn->executeQuery('SELECT * FROM t WHERE id = ' . $request->query->get('id'));",
    "sprintf %s": "$q = sprintf(\"SELECT * FROM t WHERE n = '%s'\", $_GET['n']);\nmysql_query($q);",
    "client header": "$ip = $_SERVER['HTTP_X_FORWARDED_FOR'];\nmysqli_query($c, \"INSERT INTO log VALUES ('$ip')\");",
    "escaping undone": "$n = stripslashes(addslashes($_GET['n']));\nmysqli_query($c, \"SELECT * FROM t WHERE n = '$n'\");",
    "loose regex check": "if (preg_match('/^.*$/', $_GET['n'])) { mysqli_query($c, \"SELECT * FROM t WHERE n = '\" . $_GET['n'] . \"'\"); }",
    "forbidden characters, but no exit": (
        "$p = $_POST['p'];\nif (preg_match('/[^a-z0-9_]/i', $p)) { log_it('bad'); }\n$db->query(\"SELECT $p\");"
    ),
    "heredoc query": "$n = $_COOKIE['n'];\n$q = <<<SQL\nSELECT * FROM t WHERE n = '$n'\nSQL;\npg_query($c, $q);",
    "prepare with concatenated SQL": "$stmt = $pdo->prepare('SELECT * FROM t WHERE id = ' . $_REQUEST['id']);",
}

SQL_SAFE = {
    "configuration value": "$db = $config['db'];\nmysqli_query($c, 'USE ' . $db);",
    "escaped inside quotes": "$n = mysqli_real_escape_string($c, $_GET['n']);\nmysqli_query($c, \"SELECT * FROM t WHERE n = '$n'\");",
    "integer cast": "$id = (int) $_GET['id'];\nmysqli_query($c, \"SELECT * FROM t WHERE id = $id\");",
    "sprintf %d": "mysql_query(sprintf('SELECT * FROM t WHERE id = %d', $_GET['id']));",
    "bound parameter": "$s = $pdo->prepare('SELECT * FROM t WHERE id = ?');\n$s->execute([$_GET['id']]);",
    "Laravel bindings": "DB::select('select * from users where id = ?', [$request->id]);",
    "check, then exit": "if (!is_numeric($_GET['id'])) { exit; }\nmysqli_query($c, 'SELECT * FROM t WHERE id = ' . $_GET['id']);",
    "guarded block": "$id = $_GET['id'];\nif (ctype_digit($id)) { mysqli_query($c, \"SELECT * FROM t WHERE id = $id\"); }",
    "allowlist ternary": "$s = in_array($_GET['s'], ['name', 'date'], true) ? $_GET['s'] : 'name';\n$pdo->query('SELECT * FROM t ORDER BY ' . $s);",
    "anchored regex": "$n = $_GET['n'];\nif (preg_match('/^[a-z0-9_]+$/', $n) === 1) { mysqli_query($c, \"SELECT * FROM t WHERE n = '$n'\"); }",
    "forbidden characters, then a terminating call": (
        "$p = trim($_POST['p']);\nif (preg_match('|[^a-z0-9_]|i', $p)) { wp_die('bad'); }\n$db->query(\"SELECT $p\");"
    ),
    "typed request value": "DB::statement('DELETE FROM t WHERE id = ' . $request->integer('id'));",
    "other function's variable": "function a() { $x = $_GET['x']; }\nfunction b($c, $x) { mysqli_query($c, \"SELECT * FROM t WHERE x = '$x'\"); }",
    "intval over a list": "$ids = implode(',', array_map('intval', $_GET['ids']));\nmysqli_query($c, \"SELECT * FROM t WHERE id IN ($ids)\");",
    "sink in a comment": "// mysqli_query($c, $_GET['x']);\n# pg_query($_GET['x']);\n/* $pdo->query($_GET['x']); */",
    "sink text in a string": "echo \"mysqli_query(\\$c, \\$_GET['x'])\";",
}


@pytest.mark.parametrize("code", SQL_FLOWS.values(), ids=SQL_FLOWS.keys())
def test_request_input_reaching_sql_text_is_reported(code: str) -> None:
    assert P.SQL in _kinds(code)


@pytest.mark.parametrize("code", SQL_SAFE.values(), ids=SQL_SAFE.keys())
def test_guarded_or_unrelated_sql_is_not_reported(code: str) -> None:
    assert P.SQL not in _kinds(code)


def test_hit_names_sink_and_source_lines() -> None:
    [hit] = P.scan("<?php\n$id = $_GET['id'];\n\n$q = \"SELECT '$id'\";\nmysqli_query($c, $q);\n")
    assert (hit.sink, hit.line, hit.src_line) == (P.SQL, 5, 2)


# --- shell -------------------------------------------------------------------

SHELL_FLOWS = {
    "denylist replacement": "$h = str_replace(';', '', $_GET['host']);\nshell_exec(\"ping -c 1 $h\");",
    "backticks": "$out = `nslookup {$_POST['d']}`;",
    "addslashes inside single quotes": "system(\"cat '\" . addslashes($_GET['f']) . \"'\");",
    "Symfony shell command line": "Process::fromShellCommandline('convert ' . $request->get('file'));",
    "escapeshellcmd only": "exec(escapeshellcmd('tar -xf ' . $_GET['f']));",
    "encoded quotes inside double quotes": "system('ls \"' . htmlspecialchars($_GET['d'], ENT_QUOTES) . '\"');",
    "alternative syntax": "if ($_GET['go']):\n  passthru('ls ' . $_GET['dir']);\nendif;",
}

SHELL_SAFE = {
    "escapeshellarg": "system('ping -c 1 ' . escapeshellarg($_GET['host']));",
    "argument array": "proc_open(['ping', '-c', '1', $_GET['h']], $spec, $pipes);",
    "validated parts": (
        "$o = explode('.', $_GET['ip']);\n"
        "if (count($o) == 4 && is_numeric($o[0]) && is_numeric($o[1]) && is_numeric($o[2]) && is_numeric($o[3])) {\n"
        "  $ip = $o[0] . '.' . $o[1] . '.' . $o[2] . '.' . $o[3];\n  shell_exec('ping ' . $ip);\n}"
    ),
    "upload temp path": "exec('file ' . $_FILES['f']['tmp_name']);",
    "encoded quotes inside single quotes": "system(\"ls '\" . htmlspecialchars($_GET['d'], ENT_QUOTES) . \"'\");",
    "method named exec": "$pdo->exec('VACUUM');\n$curl = curl_exec($ch . $_GET['x']);",
}


@pytest.mark.parametrize("code", SHELL_FLOWS.values(), ids=SHELL_FLOWS.keys())
def test_request_input_reaching_a_shell_is_reported(code: str) -> None:
    assert P.SHELL in _kinds(code)


@pytest.mark.parametrize("code", SHELL_SAFE.values(), ids=SHELL_SAFE.keys())
def test_escaped_validated_or_shell_free_commands_are_not_reported(code: str) -> None:
    assert P.SHELL not in _kinds(code)


# --- lexer and limits --------------------------------------------------------


def test_inline_html_and_attributes_do_not_break_the_flow() -> None:
    code = (
        "$id = $_GET['id']; ?>\n<p>Hello <?= $name ?></p>\n<?php\n"
        "#[Route('/x')]\nfunction keep() {}\n"
        "mysqli_query($c, \"SELECT * FROM t WHERE id = '$id'\");\n"
    )
    assert _sinks(code) == [(P.SQL, 7)]


def test_session_data_is_not_request_input() -> None:
    assert _sinks("mysqli_query($c, \"SELECT * FROM t WHERE id = '{$_SESSION['id']}'\");") == []


def test_deeply_nested_code_yields_no_hits_instead_of_failing() -> None:
    assert P.scan("<?php " + "(" * 5000 + "$_GET['x']" + ")" * 5000 + ";") == []


def test_regex_judgement() -> None:
    assert P._restrictive_regex("/^[A-Za-z0-9_-]+$/")
    assert P._restrictive_regex("#^\\d{1,5}\\z#")
    assert not P._restrictive_regex("/^.*$/")
    assert not P._restrictive_regex("/^[a-z]+$/m")  # multiline: ^ and $ match at every line
    assert not P._restrictive_regex("/[a-z]+/")  # unanchored
    assert not P._restrictive_regex("/^[^']+$/")
