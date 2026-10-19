"""model/case_postchecks.py: deterministic post-checks of test case claims (REQ-040).

A model investigation claims a weakness or a control at a route. Each
post-check is a fixed function over the facts ``model/case_candidates.py``
recorded from the scanner snapshot, and returns ``confirmed``,
``contradicted`` or ``not_verifiable`` with a fixed reason:

* ``route-registered``: the route inventory knows the route at the anchor.
* ``handler-chain-lacks-guard`` with guard ``authentication``: the route's
  authentication signal (``route_inventory.route_authenticated``) and its
  resolved handler chain. A chain that only decodes a token, or checks no
  credential at all, is no authentication, whatever the guard is called.
* ``handler-chain-lacks-guard`` with guard ``authorization``: the route's
  authorization signal and an AUTHZ-301/302 scanner hit at the registration.
  An unknown signal is not an absent one.
* ``handler-chain-lacks-guard`` with guard ``ownership``: the ownership
  predicate and object access of the comment-blanked handler code
  (``authz_confirm.has_ownership_predicate`` and ``_object_access``), so a
  check written only in a comment never confirms a control.

The check name and guard come from the catalog's ``post[]``; a catalog
``pattern`` is never interpreted. The model supplies only a route ID and an
anchor, and both are validated against the inventory and the admitted files:
a malformed or unknown value yields ``not_verifiable`` with a fixed reason and
never an exception or a reason that repeats the value.

``variant_search`` lists the component's routes that share a reviewed route's
handler module or resource and also access an object by identifier. They are
unreviewed variants for the model to examine, never findings.
"""

from __future__ import annotations

import posixpath
import re
from typing import Any, Iterable, Mapping

from analyzers.route_inventory import _AUTHZ_PRESENT, route_authenticated

from model.case_candidates import _component

CONFIRMED = "confirmed"
CONTRADICTED = "contradicted"
NOT_VERIFIABLE = "not_verifiable"

CHECKS = ("route-registered", "handler-chain-lacks-guard", "variant-search")
CLAIMS = ("weakness", "control")
#: Route IDs listed per variant search; ``count`` stays complete.
MAX_VARIANTS = 40

_ROUTE_ID_RE = re.compile(r"R-[0-9]{1,6}")
_MAX_ANCHOR_PATH = 1024
_MAX_ANCHOR_LINE = 10_000_000
# Scanner rules that report missing authorization at a route registration.
_AUTHZ_SCANNER_RULES = frozenset({"AUTHZ-301", "AUTHZ-302"})

UNKNOWN_CHECK = "the check is not one of the fixed post-checks"
UNKNOWN_CLAIM = "the claim is neither a weakness nor a control"
UNKNOWN_GUARD = "the guard is not one of authentication, authorization or ownership"
NO_VERDICT = "variant search lists unreviewed variants and decides no claim"
MALFORMED = "the check parameters are malformed"
UNKNOWN_ROUTE = "the route is not in the route inventory"
BAD_ANCHOR = "the anchor is not a repository-relative file and line inside the examined sources"
MISMATCH = "the anchor is neither the route's registration nor in its resolved handler chain"
REGISTERED = "the route inventory registers the route at the anchor"
AUTHN_DECODE_ONLY = "the resolved handler chain only decodes a token without verifying its signature"
AUTHN_ABSENT = "the resolved handler chain checks no credential"
AUTHN_PRESENT = "the route inventory shows an authentication guard for the route"
AUTHN_UNKNOWN = "the route inventory cannot tell whether the route is authenticated"
AUTHN_NAME_ONLY = "a guard is named at the route but the resolved handler chain does not verify a credential"
AUTHZ_PRESENT = "a guard named for authorization is registered at the route, which does not prove it enforces anything"
AUTHZ_SCANNER = "a deterministic scanner reports missing authorization at the route's registration"
AUTHZ_UNKNOWN = "the route inventory shows no authorization guard, which does not prove its absence"
OWNER_UNREAD = "the route's handler code could not be resolved"
OWNER_PREDICATE = "the handler code compares the object's owner with the caller and rejects a mismatch"
OWNER_MISSING = "the handler code accesses an object by identifier without an ownership comparison"
OWNER_NO_ACCESS = "the handler code shows no object access by identifier"


def run_check(
    check: Mapping[str, Any], claim: str, params: Mapping[str, Any], facts: Mapping[str, Any]
) -> dict[str, str]:
    """``{result, reason}`` of one catalog post-check on a model claim about a route.

    ``check`` is an entry of the catalog's ``post[]``, ``claim`` is ``weakness``
    or ``control``, and ``params`` are the model's ``{route_id, anchor}`` with
    ``anchor`` as ``{file, line}``."""
    name = check.get("check") if isinstance(check, Mapping) else None
    if not isinstance(name, str) or name not in CHECKS:
        return _result(NOT_VERIFIABLE, UNKNOWN_CHECK)
    if not isinstance(claim, str) or claim not in CLAIMS:
        return _result(NOT_VERIFIABLE, UNKNOWN_CLAIM)
    if name == "variant-search":
        return _result(NOT_VERIFIABLE, NO_VERDICT)
    guard = check.get("guard")
    evaluate = _GUARDS.get(guard) if isinstance(guard, str) else None
    if name == "handler-chain-lacks-guard" and evaluate is None:
        return _result(NOT_VERIFIABLE, UNKNOWN_GUARD)
    row, problem = _route(params, facts)
    if row is None:
        return _result(NOT_VERIFIABLE, problem)
    if name == "route-registered":
        return _result(CONFIRMED, REGISTERED)
    return evaluate(row, claim == "weakness")


def variant_search(
    case: Mapping[str, Any], component_id: str, facts: Mapping[str, Any], reviewed_route_ids: Iterable[str]
) -> dict[str, dict]:
    """``{unreviewed_variants: {count, route_ids}}`` of one component for a test case with a variant search.

    A variant is a route of the same component that no reviewed route covers,
    shares a reviewed route's handler module or resource (its path up to the
    first parameter), and whose handler accesses an object by identifier.
    Reviewed routes of other components are ignored, so the search never
    leaves the component."""
    from contexts.multi_repo_analysis import route_resource

    variants: list[str] = []
    searched = any(isinstance(entry, Mapping) and entry.get("check") == "variant-search" for entry in case["post"])
    if searched:
        own = _component(facts, component_id)["route_ids"]
        routes = facts["routes"]
        listed = reviewed_route_ids if isinstance(reviewed_route_ids, (list, tuple, set, frozenset)) else []
        reviewed = {route_id for route_id in listed if isinstance(route_id, str)} & set(own)
        modules = {routes[route_id]["handler_module"] for route_id in reviewed} - {None}
        resources = {route_resource(routes[route_id]["path"]) for route_id in reviewed}
        variants = [
            route_id
            for route_id in own
            if route_id not in reviewed
            and routes[route_id]["object_access"]
            and (routes[route_id]["handler_module"] in modules or route_resource(routes[route_id]["path"]) in resources)
        ]
    return {"unreviewed_variants": {"count": len(variants), "route_ids": variants[:MAX_VARIANTS]}}


# --- parameters ---------------------------------------------------------------


def _route(params: Any, facts: Mapping[str, Any]) -> tuple[dict | None, str | None]:
    """The inventory row the parameters name, or None and the fixed reason it cannot be used."""
    if not isinstance(params, Mapping):
        return None, MALFORMED
    route_id = params.get("route_id")
    if not isinstance(route_id, str) or not _ROUTE_ID_RE.fullmatch(route_id) or route_id not in facts["routes"]:
        return None, UNKNOWN_ROUTE
    anchor = _anchor(params.get("anchor"), facts)
    if anchor is None:
        return None, BAD_ANCHOR
    row = facts["routes"][route_id]
    file, line = anchor
    registered = (file, line) == (row["handler_file"], row["handler_line"])
    if not registered and not any(file == rel and first <= line <= last for rel, first, last in row["chain"]):
        return None, MISMATCH
    return row, None


def _anchor(value: Any, facts: Mapping[str, Any]) -> tuple[str, int] | None:
    """``(file, line)`` of an anchor naming an admitted repository file, else None.

    The path must be relative and normalized, without parent segments; the
    admitted files were recorded without symlinks that leave the repository."""
    if not isinstance(value, Mapping):
        return None
    file, line = value.get("file"), value.get("line")
    if not isinstance(file, str) or type(line) is not int or not 1 <= line <= _MAX_ANCHOR_LINE:
        return None
    if not file or len(file) > _MAX_ANCHOR_PATH or "\x00" in file or "\\" in file:
        return None
    if file.startswith("/") or posixpath.normpath(file) != file or ".." in file.split("/"):
        return None
    return (file, line) if file in set(facts["files"]) else None


# --- guards -------------------------------------------------------------------


def _result(result: str, reason: str) -> dict[str, str]:
    return {"result": result, "reason": reason}


def _authentication(row: Mapping[str, Any], weakness: bool) -> dict[str, str]:
    """The resolved chain decides over a guard's name; a name without a verifying chain proves nothing either way."""
    if row["authn_handler_signal"] == "decode_only":
        return _result(CONFIRMED if weakness else CONTRADICTED, AUTHN_DECODE_ONLY)
    if row["authn_signal"] == "absent" or row["authn_handler_signal"] == "none":
        return _result(CONFIRMED if weakness else CONTRADICTED, AUTHN_ABSENT)
    if route_authenticated(row):
        if row["authn_handler_signal"] == "verified":
            return _result(CONTRADICTED if weakness else CONFIRMED, AUTHN_PRESENT)
        # A guard's name alone is not a verified check: analysed code could earn a confirmed control by naming a function.
        return _result(NOT_VERIFIABLE, AUTHN_NAME_ONLY)
    return _result(NOT_VERIFIABLE, AUTHN_UNKNOWN)


def _authorization(row: Mapping[str, Any], weakness: bool) -> dict[str, str]:
    if _AUTHZ_SCANNER_RULES & set(row["scanner_rules"]):
        # A control the scanner reports missing at the same registration is no confirmed control.
        return _result(CONFIRMED if weakness else CONTRADICTED, AUTHZ_SCANNER)
    if row["authz_signal"] in _AUTHZ_PRESENT:
        # The inventory knows a guard only by its name; analysed code could earn a control by naming a function.
        return _result(NOT_VERIFIABLE, AUTHZ_PRESENT)
    return _result(NOT_VERIFIABLE, AUTHZ_UNKNOWN)


def _ownership(row: Mapping[str, Any], weakness: bool) -> dict[str, str]:
    if not row["handler_read"]:
        return _result(NOT_VERIFIABLE, OWNER_UNREAD)
    if row["ownership_predicate"]:
        return _result(CONTRADICTED if weakness else CONFIRMED, OWNER_PREDICATE)
    if row["object_access"]:
        return _result(CONFIRMED if weakness else CONTRADICTED, OWNER_MISSING)
    return _result(NOT_VERIFIABLE, OWNER_NO_ACCESS)


_GUARDS = {"authentication": _authentication, "authorization": _authorization, "ownership": _ownership}
