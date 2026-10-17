"""Operator-owned scan profiles and bounded, role-specific model settings.

Profiles contain data only. They cannot supply credentials, destinations,
commands, tools, prices, or claims of model qualification.
"""

from __future__ import annotations

import copy
import hashlib
import json
import math
import os
import re
import stat
from itertools import islice
from pathlib import Path, PurePosixPath

import yaml
from jsonschema import Draft202012Validator
from yaml.tokens import AliasToken, AnchorToken

from appsec_analyzer import resource_root

BUILTINS = ("claude", "codex")
DEPTHS = ("quick", "standard", "thorough")
OUTPUTS = ("markdown", "yaml", "html", "pdf", "sarif", "threatdragon", "pentest-tasks")
ROLES = (
    "abuse_case_deriver",
    "abuse_case_verifier",
    "actor_discoverer",
    "architecture_analyst",
    "architect_reviewer",
    "control_analyst",
    "evidence_verifier",
    "post_stride_synthesizer",
    "recon_scanner",
    "stride_analyzer",
    "threat_merger",
    "triage_validator",
    "trust_boundary_analyst",
    "ms_renderer",
    "secarch_renderer",
)
NAME = re.compile(r"[a-z][a-z0-9-]{0,63}")
MAX_BYTES = 65_536


class ProfileError(ValueError):
    """A configuration error safe to show without echoing profile values."""


class _Loader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        result = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            if not isinstance(key, str) or key in result:
                raise ProfileError("profile keys must be unique strings")
            result[key] = self.construct_object(value_node, deep=deep)
        return result


def config_home() -> Path:
    root = os.environ.get("XDG_CONFIG_HOME")
    if root and not Path(root).is_absolute():
        raise ProfileError("XDG_CONFIG_HOME must be an absolute directory")
    return (Path(root) if root else Path.home() / ".config") / "appsec-analyzer"


def reject_source_paths(paths, repositories) -> None:
    for selection in repositories:
        if "://" in str(selection) or str(selection).startswith("git@"):
            continue
        root = Path(selection).resolve()
        for parent in (root, *root.parents):
            if (parent / ".git").exists():
                root = parent
                break
        if any(Path(path).resolve().is_relative_to(root) for path in paths):
            raise ProfileError("profile files must be outside the analyzed repositories")


def read_document(path: Path, *, repositories=()) -> dict:
    """Read bounded data without links, YAML aliases, duplicate keys, or tags."""
    path = path.expanduser().absolute()
    reject_source_paths([path], repositories)
    if path.resolve() != path or path.suffix != ".yaml":
        raise ProfileError("profile must be a .yaml file without symlinks")
    try:
        # Open each directory without following links, including a parent
        # replaced between the path check and opening the file.
        parent_fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for part in path.parts[1:-1]:
                next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd)
                os.close(parent_fd)
                parent_fd = next_fd
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent_fd)
        finally:
            os.close(parent_fd)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > MAX_BYTES:
                raise ProfileError("profile must be a bounded, singly linked regular file")
            raw = stream.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ProfileError("profile exceeds 64 KiB")
        text = raw.decode("utf-8")
        count = 0
        for token in yaml.scan(text):
            count += 1
            if isinstance(token, (AliasToken, AnchorToken)) or count > 10000:
                raise ProfileError("profile YAML aliases and excessive nesting are unsupported")
        value = yaml.load(text, Loader=_Loader)
        if not isinstance(value, dict):
            raise ProfileError("profile must contain a mapping")
        # Also rejects non-finite numbers before JSON Schema's numeric checks.
        json.dumps(value, allow_nan=False)
        return value
    except ProfileError:
        raise
    except (OSError, UnicodeError, yaml.YAMLError, ValueError, TypeError, RecursionError):
        raise ProfileError("profile is missing, unreadable, or contains invalid YAML") from None


def validate(document: dict, kind: str) -> None:
    schema = yaml.safe_load((resource_root() / f"schemas/{kind}-profile.schema.yaml").read_text())
    error = next(Draft202012Validator(schema).iter_errors(document), None)
    if error:
        # Do not print the instance: a mistyped field may hold a credential.
        location = ".".join(str(p) for p in error.schema_path if p != "properties")
        raise ProfileError(f"invalid {kind} profile ({location})")


def catalog() -> dict:
    return yaml.safe_load((resource_root() / "data/model-catalog.yaml").read_text())


def _builtin(name: str, kind: str) -> dict:
    path = resource_root() / f"data/{kind}-profiles/{name}.yaml"
    document = read_document(path)
    validate(document, kind)
    return document


def _select(selection: str, kind: str, *, home: Path, repositories=()) -> tuple[dict, str, list[str]]:
    folder = "profiles" if kind == "scan" else "model-profiles"
    if NAME.fullmatch(selection):
        candidate = home / folder / f"{selection}.yaml"
        if selection in BUILTINS:
            if os.path.lexists(candidate):
                raise ProfileError(f"user {kind} profile conflicts with reserved name {selection}")
            return _builtin(selection, kind), f"builtin:{selection}", []
        path = candidate
    elif kind == "scan":
        path = Path(selection).expanduser().absolute()
        if not NAME.fullmatch(path.stem):
            raise ProfileError("profile filenames use lowercase letters, digits, and hyphens")
        if path.stem in BUILTINS:
            raise ProfileError("custom profiles cannot use a reserved built-in name")
    else:
        raise ProfileError("model_profile must name a profile, not a path")
    doc = read_document(path, repositories=repositories)
    validate(doc, kind)
    return doc, str(path), [str(path)]


def _assign(target, origin, values, label):
    for key, value in values.items():
        target[key] = copy.deepcopy(value)
        origin[key] = label


def model_settings(selection: str, depth: str, *, home=None, repositories=()) -> dict:
    if depth not in DEPTHS:
        raise ProfileError("unsupported assessment depth")
    home = home or config_home()
    own, source, files = _select(selection, "model", home=home, repositories=repositories)
    base_name = own.get("base")
    layers = [(_builtin(base_name, "model"), f"builtin:{base_name}")] if base_name else []
    layers.append((own, source))
    adapter = layers[0][0]["adapter"]
    definitions, origins = {}, {}
    # Custom defaults override inherited role defaults; within each layer the
    # depth default precedes the role and the depth's role is most specific.
    for role in ROLES:
        settings, provenance = {}, {}
        for layer, label in layers:
            depth_layer = layer.get("depths", {}).get(depth, {})
            for values, suffix in (
                (layer.get("defaults", {}), "defaults"),
                (depth_layer.get("defaults", {}), f"depths.{depth}.defaults"),
                (layer.get("roles", {}).get(role, {}), f"roles.{role}"),
                (depth_layer.get("roles", {}).get(role, {}), f"depths.{depth}.roles.{role}"),
            ):
                _assign(settings, provenance, values, f"{label}:{suffix}")
        definitions[role], origins[role] = settings, provenance
    return {
        "adapter": adapter,
        "definitions": definitions,
        "origins": origins,
        "files": files,
        "layers": [layer for layer, _ in layers],
    }


def resolve_model(settings: dict, adapter: str, *, saved_model: str | None = None) -> dict:
    requested = settings.get("model")
    if not requested:
        raise ProfileError("every model role needs a model default or override")
    result = {**settings, "requested_model": requested}
    if adapter == "openai":
        registry = catalog()
        model = saved_model or registry["aliases"].get(requested, requested)
        if saved_model and requested not in registry["aliases"] and model != requested:
            raise ProfileError("saved profile changes an explicit model selection")
        entry = registry["models"].get(model)
        if not entry or entry["adapter"] != adapter:
            raise ProfileError("model is not in the installed OpenAI model catalog")
        result["model"] = model
        result.setdefault("reasoning_effort", "medium")
        result["model_output_limit"] = entry["max_output_tokens"]
        if result["reasoning_effort"] not in entry["reasoning_efforts"]:
            raise ProfileError("reasoning effort is unsupported by the selected model")
        if "max_output_tokens" in result and not 1 <= result["max_output_tokens"] <= entry["max_output_tokens"]:
            raise ProfileError("output token limit exceeds the selected model's capacity")
        for key in ("input_usd_per_million", "output_usd_per_million"):
            result[key] = entry[key]
        result["price_revision"] = registry["price_revision"]
    else:
        if not re.fullmatch(r"(?:sonnet|haiku|opus|claude-[a-z0-9][a-z0-9.-]{0,100})", requested):
            raise ProfileError("Claude model must be sonnet, haiku, opus, or a claude- model ID")
        if "max_output_tokens" in result:
            raise ProfileError("Claude CLI does not expose max_output_tokens; use the USD budget")
        if result.get("reasoning_effort") not in (None, "low", "medium", "high", "xhigh", "max"):
            raise ProfileError("unsupported Claude CLI reasoning effort")
    return result


def _case_files(values: list[str]) -> list[str]:
    """Validate operator selections without reading beyond the admitted source snapshot."""
    validate({"schema_version": 1, "abuse_case_files": values}, "scan")
    paths = []
    for value in values:
        path = PurePosixPath(value)
        if path.is_absolute() or ".." in path.parts or "\\" in value or ":" in value:
            raise ProfileError("abuse-case files must be repository-relative paths without traversal")
        if path.suffix not in (".yaml", ".yml"):
            raise ProfileError("abuse-case files must have a .yaml or .yml extension")
        if path.as_posix() not in paths:
            paths.append(path.as_posix())
    return paths


def resolve_scan(
    selection: str, *, depth=None, budget=None, outputs=None, abuse_case_files=None, repositories=(), home=None
) -> dict:
    home = home or config_home()
    scan, source, files = _select(selection, "scan", home=home, repositories=repositories)
    # An explicit scan file finds model files only in its sibling model-profiles
    # directory, so a shared team configuration does not depend on user defaults.
    model_home = Path(source).parent.parent if files else home
    settings = {
        "model_profile": "claude",
        "assessment_depth": "standard",
        "budget": 20,
        "outputs": ["markdown", "yaml"],
        "abuse_case_files": [],
    }
    provenance = {key: "analyzer default" for key in settings}
    _assign(settings, provenance, {k: v for k, v in scan.items() if k in settings}, source)
    for key, value in (
        ("assessment_depth", depth),
        ("budget", budget),
        ("outputs", outputs),
        ("abuse_case_files", abuse_case_files),
    ):
        if value is not None:
            _assign(settings, provenance, {key: value}, "CLI")
    settings["abuse_case_files"] = _case_files(settings["abuse_case_files"])
    if type(settings["budget"]) not in (int, float) or not math.isfinite(settings["budget"]) or settings["budget"] <= 0:
        raise ProfileError("budget must be a positive finite USD amount")
    if any(item not in OUTPUTS for item in settings["outputs"]):
        raise ProfileError("unsupported output format")
    selected_outputs = set(settings["outputs"]) | {"markdown", "yaml"}
    settings["outputs"] = [item for item in OUTPUTS if item in selected_outputs]
    model = model_settings(
        settings["model_profile"], settings["assessment_depth"], home=model_home, repositories=repositories
    )
    definition = {"scan": scan, "models": model["layers"], "settings": settings}
    fingerprint = hashlib.sha256(json.dumps(definition, sort_keys=True).encode()).hexdigest()
    resolved = {role: resolve_model(values, model["adapter"]) for role, values in model["definitions"].items()}
    return {
        "schema_version": 1,
        "name": selection if NAME.fullmatch(selection) else Path(selection).stem,
        "description": scan.get("description", ""),
        "adapter": model["adapter"],
        "settings": settings,
        "attributes": scan.get("report", {}).get("attributes", {}),
        "models": resolved,
        "origins": {"settings": provenance, "models": model["origins"]},
        "definition_sha256": fingerprint,
        "files": files + model["files"],
        "qualified": False,
    }


def api_profile(settings: dict):
    from appsec_analyzer.api_hosts import ApiProfile

    return ApiProfile(
        kind="openai",
        endpoint="https://api.openai.com/v1/responses",
        key_env="OPENAI_API_KEY",
        model=settings["model"],
        input_usd_per_million=settings["input_usd_per_million"],
        output_usd_per_million=settings["output_usd_per_million"],
        price_revision=settings["price_revision"],
        reasoning_effort=settings["reasoning_effort"],
        max_output_tokens=settings.get("max_output_tokens"),
        model_output_limit=settings["model_output_limit"],
        max_request_bytes=240_000,
    )


def call_reservation(profile: dict) -> float:
    bounds = []
    for settings in profile["models"].values():
        api = api_profile(settings)
        bounds.append(
            (
                (api.max_request_bytes + 4096) * api.input_usd_per_million
                + api.output_token_bound * api.output_usd_per_million
            )
            / 1_000_000
        )
    return math.ceil(max(bounds) * 100) / 100


def restore_profile(profile: dict, output: Path, *, resume: bool) -> dict:
    """Freeze alias resolutions across resume, then recheck against the catalog.

    The normal lifecycle identity check still binds every effective setting.
    Saved state never supplies an endpoint, credential, price, or tool grant.
    """
    result = copy.deepcopy(profile)
    if not resume:
        return result
    from runtime.assessment_state import STATE_NAME, _read_state

    path = output / STATE_NAME
    if not os.path.lexists(path):
        return result
    saved = _read_state(path).get("operator_profile")
    if not saved or saved.get("definition_sha256") != profile["definition_sha256"]:
        raise ProfileError("profile settings changed or predate profile snapshots; start a new run")
    if result["adapter"] != "openai":
        return result
    for role, settings in result["models"].items():
        previous = saved.get("models", {}).get(role, {})
        if previous.get("requested_model") != settings["requested_model"]:
            raise ProfileError("saved profile model request differs from the selected profile")
        options = {key: settings[key] for key in ("reasoning_effort", "max_output_tokens") if key in settings}
        options["model"] = settings["requested_model"]
        result["models"][role] = resolve_model(options, result["adapter"], saved_model=previous.get("model"))
    return result


def apply_runtime_profile(profile: dict, cfg: dict, arguments: list[str], *, model=None) -> None:
    """Apply typed settings after organization defaults, before session identity."""
    from orchestrator.assessment_stage2 import RENDERER_MODEL_KEYS
    from orchestrator.orchestration_controller import SEMANTIC_ROLE_MODEL_KEYS
    from runtime import resolve_config

    selected = resolve_config.build_parser().parse_known_args(arguments)[0]
    keys = {**SEMANTIC_ROLE_MODEL_KEYS, **RENDERER_MODEL_KEYS}
    legacy = dict(cfg)
    for role, settings in profile["models"].items():
        if profile["adapter"] == "claude-cli":
            # Preserve the existing environment/CLI/depth routing where the
            # operator did not select their own model value.
            origin = profile["origins"]["models"][role].get("model", "")
            chosen = legacy.get(keys[role]) if origin.startswith("builtin:") else None
            if model:
                chosen = model
            flag = {
                "stride_analyzer": "stride_model",
                "triage_validator": "triage_model",
                "post_stride_synthesizer": "triage_model",
                "threat_merger": "merger_model",
            }.get(role)
            if flag and getattr(selected, flag, None):
                chosen = getattr(selected, flag)
            if chosen:
                settings.update(
                    resolve_model(
                        {"model": chosen, "reasoning_effort": settings.get("reasoning_effort", "medium")}, "claude-cli"
                    )
                )
                profile["origins"]["models"][role]["model"] = "Claude controller/CLI"
            if cfg.get("opus_disabled") and "opus" in settings["model"]:
                raise ProfileError("model profile conflicts with the organization Opus restriction")
        cfg[keys[role]] = settings["model"]
    for output in OUTPUTS[2:]:
        cfg["write_" + output.replace("-", "_")] = output in profile["settings"]["outputs"]
    cfg["operator_profile"] = copy.deepcopy(profile)


def list_profiles() -> list[dict]:
    home = config_home()
    results = []
    for kind, folder in (("scan", "profiles"), ("model", "model-profiles")):
        for name in BUILTINS:
            results.append({"kind": kind, "name": name, "source": "built-in"})
        directory = home / folder
        if directory.exists():
            if directory.resolve() != directory:
                raise ProfileError("profile directories must not be symlinks")
            entries = list(islice(directory.iterdir(), 257))
            if len(entries) > 256:
                raise ProfileError("profile directory contains too many entries")
            for path in sorted(entries):
                if path.suffix != ".yaml" or not NAME.fullmatch(path.stem):
                    continue
                if path.stem in BUILTINS:
                    raise ProfileError("user profile conflicts with a reserved built-in name")
                results.append({"kind": kind, "name": path.stem, "source": str(path)})
    return results
