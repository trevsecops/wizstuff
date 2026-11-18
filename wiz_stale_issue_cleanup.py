#!/usr/bin/env python3
"""
Wiz Stale Issue Cleanup
=======================

Finds Issues that are still open on controls that are DISABLED in Wiz, and closes them out of
the open queue with a note that says why.

IMPORTANT - what "close" means here
    Wiz does not allow Graph Control or Cloud Configuration Issues to be set to RESOLVED by a user or
    through the API. Only Wiz resolves them, during its own scans (docs.wiz.io/dev/update-issue-tutorial).
    The only manual way to take such an Issue out of the open queue is to IGNORE it, which Wiz stores as
    status REJECTED with a reason (Won't fix / Exception / False positive). That is what this script does:

        1. adds a comment to the Issue explaining that it is stale     (createCommentThreadComment)
        2. sets the Issue to REJECTED with the chosen reason           (updateIssue)

    An ignored Issue stays ignored. If the control is ever re-enabled, the same control + resource pairs
    stay silenced until they are reopened. The journal this script writes lets you reopen them (--revert).

Modes
    (default)            PLAN. Reads only. Lists every disabled control that still has open Issues and
                         writes the workbook showing what would be done. Changes nothing.
    --execute            Makes the changes. Needs --controls or --all-disabled, and a typed confirmation.
    --execute --limit N  Pilot: only the first N Issues.
    --revert JOURNAL     Reopens the Issues that an earlier run ignored (add --execute to apply).

Outputs (prefix set by -o, default Wiz_Stale_Issue_Cleanup_<UTC timestamp>)
    <prefix>.xlsx            Summary, By Control, Issues (one row per Issue with the result), Skipped Controls
    <prefix>_summary.txt     Plain-text summary of what was done
    <prefix>_journal.jsonl   One line per Issue as it is processed. Crash-safe. Used by --resume and --revert

Service account (Custom Integration (GraphQL API)). Use a dedicated account for this job and remove it after.
    read:controls, read:issues                    plan
    write:issue_ignore, write:issue_status        set Issues to Ignored / reopen them
    write:comments                                add the explanatory comment

Credentials only through environment variables:
    WIZ_CLIENT_ID, WIZ_CLIENT_SECRET, WIZ_API_URL (optional, derived from the token), WIZ_AUTH_URL, WIZ_AUDIENCE

Usage
    python wiz_stale_issue_cleanup.py                                             # plan
    python wiz_stale_issue_cleanup.py --controls wc-id-1,wc-id-2 --execute --limit 5 --reference CHG0012345
    python wiz_stale_issue_cleanup.py --all-disabled --execute --reference CHG0012345
    python wiz_stale_issue_cleanup.py --revert Wiz_Stale_Issue_Cleanup_X_journal.jsonl --execute

Exit codes: 0 success, 2 completed with some failures or skipped controls, 1 fatal.
Dependencies: requests, openpyxl
"""

import argparse
import base64
import getpass
import json
import logging
import os
import random
import re
import sys
import time
from collections import Counter, OrderedDict
from datetime import datetime, timezone

try:
    import requests
except ImportError:  # pragma: no cover
    sys.stderr.write("ERROR: the 'requests' package is required. Install with: pip install requests\n")
    sys.exit(1)

VERSION = "1.0.0"
# 1.0.0 (2026-11-18): initial release. Mock-tested only. First live run: plan, then --execute --limit 5.
USER_AGENT = "wiz-stale-issue-cleanup/%s" % VERSION
DEFAULT_AUTH_URL = "https://auth.app.wiz.io/oauth/token"
DEFAULT_APP_URL = "https://app.wiz.io"
ILLEGAL_XLSX_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
FIELD_ERR_RE = re.compile(r'Cannot query field "([^"]+)" on type "([^"]+)"')
ISSUE_TYPES = ["TOXIC_COMBINATION", "CLOUD_CONFIGURATION"]
REASONS = ["WONT_FIX", "EXCEPTION", "FALSE_POSITIVE"]
MAX_ROOT_FIELDS = 10   # Wiz global GraphQL limit per operation

DEFAULT_NOTE = (
    "Stale Issue. Its source control \"{control_name}\" ({control_id}) is disabled in Wiz, so this Issue is no "
    "longer evaluated and does not reflect the current state of the resource. Ignored in bulk on {date} by the "
    "Cloud Security Team as part of the stale Issue cleanup.{reference} Status before: {prior_status}. "
    "Issue created: {created}."
)
REVERT_NOTE = "Reopened on {date}. Reverses the bulk ignore applied by the stale Issue cleanup on {ignored_on}.{reference}"

log = logging.getLogger("wiz-stale-cleanup")


class WizAPIError(Exception):
    pass


class WizPermissionError(WizAPIError):
    pass


class GraphQLFieldError(WizAPIError):
    def __init__(self, message, bad_fields):
        super().__init__(message)
        self.bad_fields = bad_fields


def decode_jwt_payload(token):
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part.encode()).decode())
    except Exception:
        return {}


class WizClient:
    def __init__(self, auth_url, api_url, client_id, client_secret, audience="wiz-api", timeout=110,
                 max_retries=5, verify=True, read_pause=0.25, mutation_cps=1.0):
        self.auth_url, self.api_url = auth_url, api_url
        self.client_id, self.client_secret, self.audience = client_id, client_secret, audience
        self.timeout, self.max_retries = timeout, max_retries
        self.read_pause = read_pause
        self.mutation_interval = 1.0 / mutation_cps if mutation_cps > 0 else 0.0
        self._last_mutation = 0.0
        self.session = requests.Session()
        self.session.verify = verify
        self.session.headers.update({"User-Agent": USER_AGENT})
        self._token, self._token_exp = None, 0.0
        self.token_claims = {}
        self.read_calls = 0
        self.mutation_calls = 0

    def _fetch_token(self):
        resp = self.session.post(
            self.auth_url,
            data={"grant_type": "client_credentials", "client_id": self.client_id,
                  "client_secret": self.client_secret, "audience": self.audience},
            headers={"Content-Type": "application/x-www-form-urlencoded"}, timeout=self.timeout)
        if resp.status_code != 200:
            raise WizAPIError("Token request failed: HTTP %s from %s\n%s" % (resp.status_code, self.auth_url, resp.text[:400]))
        data = resp.json()
        self._token = data["access_token"]
        self._token_exp = time.time() + max(60, int(data.get("expires_in", 86400)) - 300)
        self.token_claims = decode_jwt_payload(self._token)

    @property
    def token(self):
        if not self._token or time.time() >= self._token_exp:
            self._fetch_token()
        return self._token

    def ensure_api_url(self):
        if self.api_url:
            return self.api_url
        _ = self.token
        dc = self.token_claims.get("dc")
        if not dc:
            raise WizAPIError("WIZ_API_URL is not set and the token carries no `dc` claim - copy the API Endpoint URL from the Wiz console")
        host = "app.wiz.us" if "wiz.us" in self.auth_url else ("gov.wiz.io" if "gov.wiz.io" in self.auth_url else "app.wiz.io")
        self.api_url = "https://api.%s.%s/graphql" % (dc, host)
        log.info("WIZ_API_URL derived from token dc claim: %s", self.api_url)
        return self.api_url

    def _post(self, query, variables):
        """One HTTP round trip with retry on rate limiting, 5xx and network errors. Returns the parsed payload."""
        attempt, refreshed = 0, False
        while True:
            attempt += 1
            try:
                resp = self.session.post(self.api_url, json={"query": query, "variables": variables or {}},
                                         headers={"Authorization": "Bearer %s" % self.token, "Content-Type": "application/json"},
                                         timeout=self.timeout)
            except requests.RequestException as exc:
                if attempt <= self.max_retries:
                    delay = min(30, 0.5 * (2 ** attempt)) + random.uniform(0, 0.5)
                    log.warning("Network error (%s); retry %d/%d in %.1fs", exc.__class__.__name__, attempt, self.max_retries, delay)
                    time.sleep(delay)
                    continue
                raise WizAPIError("Network error after %d retries: %s" % (self.max_retries, exc))
            if resp.status_code == 401 and not refreshed:
                self._token, refreshed = None, True
                continue
            if resp.status_code == 401:
                raise WizAPIError("HTTP 401 with a fresh token - check WIZ_API_URL points at this tenant's data center (%s)" % self.api_url)
            if resp.status_code == 429 or resp.status_code >= 500:
                if attempt <= self.max_retries + 3:
                    ra = resp.headers.get("Retry-After")
                    try:
                        delay = min(60, max(1, int(ra))) if ra else min(30, 0.5 * (2 ** attempt)) + random.uniform(0, 1)
                    except ValueError:
                        delay = 5
                    log.warning("HTTP %s; sleeping %.1fs (attempt %d)", resp.status_code, delay, attempt)
                    time.sleep(delay)
                    continue
                raise WizAPIError("HTTP %s after %d attempts: %s" % (resp.status_code, attempt, resp.text[:300]))
            if resp.status_code not in (200, 400):
                raise WizAPIError("HTTP %s: %s" % (resp.status_code, resp.text[:400]))
            try:
                payload = resp.json()
            except ValueError:
                raise WizAPIError("Non-JSON response: %s" % resp.text[:300])
            codes = {(e.get("extensions") or {}).get("code") for e in (payload.get("errors") or [])}
            if "RATE_LIMIT_EXCEEDED" in codes and attempt <= self.max_retries + 3:
                delay = min(30, 0.5 * (2 ** attempt)) + random.uniform(0, 1)
                log.warning("RATE_LIMIT_EXCEEDED; sleeping %.1fs", delay)
                time.sleep(delay)
                continue
            if "UNAUTHENTICATED" in codes and not refreshed:
                self._token, refreshed = None, True
                continue
            return payload

    def query(self, query, variables=None):
        """Read call. Raises on any GraphQL error."""
        payload = self._post(query, variables)
        self.read_calls += 1
        errors = payload.get("errors") or []
        if errors:
            messages = "; ".join(str(e.get("message", "")) for e in errors)[:1200]
            codes = {(e.get("extensions") or {}).get("code") for e in errors}
            bad = FIELD_ERR_RE.findall(messages)
            if bad:
                raise GraphQLFieldError(messages, bad)
            if "FORBIDDEN" in codes or "FORBIDDEN_IP" in codes:
                raise WizPermissionError(messages)
            if not payload.get("data"):
                raise WizAPIError("GraphQL error: %s" % messages)
            log.warning("Partial GraphQL errors (continuing): %s", messages)
        if self.read_pause:
            time.sleep(self.read_pause)
        return payload.get("data") or {}

    def mutate(self, query, variables=None):
        """Write call, paced to --calls-per-second. Returns (data, errors) so the caller can judge each alias."""
        wait = self.mutation_interval - (time.time() - self._last_mutation)
        if wait > 0:
            time.sleep(wait)
        payload = self._post(query, variables)
        self._last_mutation = time.time()
        self.mutation_calls += 1
        return payload.get("data") or {}, payload.get("errors") or []


# --------------------------------------------------------------------------- #
# Reads
# --------------------------------------------------------------------------- #

def build_selection(spec):
    return " ".join(("%s { %s }" % (k, build_selection(v))) if v else k for k, v in spec.items())


def remove_fields(spec, names):
    for name in list(spec.keys()):
        if name in names:
            del spec[name]
        elif isinstance(spec.get(name), dict):
            remove_fields(spec[name], names)
            if not spec[name]:
                del spec[name]


def paged(client, root, spec, filter_by, filter_type, label, page_size=500, max_pages=None, order=None):
    nodes, after, page, total, rounds = [], None, 0, None, 0
    while True:
        q = ("query Q($first: Int, $after: String, $filterBy: %s%s) { %s(first: $first, after: $after, filterBy: $filterBy%s) "
             "{ nodes { %s } pageInfo { hasNextPage endCursor } totalCount } }"
             % (filter_type, ", $orderBy: IssueOrder" if order else "", root, ", orderBy: $orderBy" if order else "", build_selection(spec)))
        variables = {"first": page_size, "after": after, "filterBy": filter_by or {}}
        if order:
            variables["orderBy"] = order
        try:
            data = client.query(q, variables)
        except GraphQLFieldError as exc:
            bad = {f for f, _ in exc.bad_fields}
            rounds += 1
            if rounds > 10:
                raise
            log.info("[%s] dropping field(s) not in this tenant's schema: %s", label, ", ".join(sorted(bad)))
            remove_fields(spec, bad)
            continue
        conn = data.get(root) or {}
        batch = [n for n in (conn.get("nodes") or []) if n]
        nodes.extend(batch)
        if conn.get("totalCount") is not None:
            total = conn["totalCount"]
        page += 1
        pi = conn.get("pageInfo") or {}
        if label:
            log.debug("[%s] page %d: +%d (running %d%s)", label, page, len(batch), len(nodes), "/%s" % total if total is not None else "")
        if not pi.get("hasNextPage") or not pi.get("endCursor") or pi.get("endCursor") == after:
            break
        if max_pages and page >= max_pages:
            break
        after = pi["endCursor"]
    return nodes, total


def fetch_controls(client):
    spec = OrderedDict([("id", None), ("name", None), ("type", None), ("severity", None), ("enabled", None),
                        ("sourceCloudConfigurationRule", OrderedDict([("id", None), ("name", None), ("shortId", None)]))])
    nodes, total = paged(client, "controls", spec, {}, "ControlFilters", "controls")
    log.info("Controls fetched: %d (API totalCount %s)", len(nodes), total)
    return nodes


def rule_ids_of(control):
    ids = [control["id"]]
    src = control.get("sourceCloudConfigurationRule")
    if isinstance(src, dict) and src.get("id"):
        ids.append(src["id"])
    return ids


def issue_filter(control, statuses):
    return {"sourceRule": {"id": rule_ids_of(control)}, "status": statuses, "type": ISSUE_TYPES}


def count_issues(client, control, statuses):
    _, total = paged(client, "issuesV2", OrderedDict([("id", None)]), issue_filter(control, statuses), "IssueFilters", None, page_size=1, max_pages=1)
    return total or 0


def fetch_issues(client, control, statuses):
    spec = OrderedDict([
        ("id", None), ("type", None), ("severity", None), ("status", None), ("createdAt", None), ("statusChangedAt", None),
        ("sourceRules", OrderedDict([("__typename", None),
                                     ("... on Control", OrderedDict([("id", None), ("name", None)])),
                                     ("... on CloudConfigurationRule", OrderedDict([("id", None), ("name", None)]))])),
        ("entitySnapshot", OrderedDict([("id", None), ("type", None), ("nativeType", None), ("name", None), ("cloudPlatform", None),
                                        ("region", None), ("subscriptionExternalId", None), ("subscriptionName", None)])),
        ("projects", OrderedDict([("id", None), ("name", None)])),
    ])
    nodes, total = paged(client, "issuesV2", spec, issue_filter(control, statuses), "IssueFilters", "issues %s" % control["id"],
                         order={"field": "CREATED_AT", "direction": "ASC"})
    return nodes, total


def issue_belongs(issue, control):
    """Defensive check: the Issue's own source rule must be this control (or its source config rule)."""
    wanted = set(rule_ids_of(control))
    for r in issue.get("sourceRules") or []:
        if isinstance(r, dict) and r.get("id") in wanted:
            return True
    return False


def probe_schema(client):
    """Which write paths exist on this tenant. Falls back to the documented ones if introspection is off."""
    info = {"comment_mutation": True, "patch_has_note": False, "introspection": False}
    try:
        data = client.query("query { __schema { mutationType { fields { name } } } }")
        names = {f["name"] for f in data["__schema"]["mutationType"]["fields"]}
        info["introspection"] = True
        info["comment_mutation"] = "createCommentThreadComment" in names
        info["update_mutation"] = "updateIssue" in names
        data = client.query('query { __type(name: "UpdateIssuePatch") { inputFields { name } } }')
        fields = {f["name"] for f in ((data.get("__type") or {}).get("inputFields") or [])}
        info["patch_has_note"] = "note" in fields
    except Exception as exc:  # noqa: BLE001
        log.info("Schema introspection not available (%s); assuming the documented mutations", str(exc)[:120])
    return info


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def parse_dt(value):
    if not value:
        return None
    try:
        v = value.replace("Z", "+00:00")
        if "." in v:
            head, tail = v.split(".", 1)
            m = re.match(r"(\d+)(.*)", tail)
            v = head + "." + m.group(1)[:6] + m.group(2)
        dt = datetime.fromisoformat(v)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def iso_z(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def clean(value, limit=32000):
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (int, float)):
        return value
    s = ILLEGAL_XLSX_RE.sub("", str(value))
    return s if len(s) <= limit else s[: limit - 15] + " ...[truncated]"


def chunks(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def render_note(template, control, issue, args, now):
    ref = (" Reference: %s." % args.reference) if args.reference else ""
    values = {"control_name": control.get("name") or "", "control_id": control.get("id") or "",
              "date": now.strftime("%Y-%m-%d"), "reference": ref,
              "prior_status": issue.get("status") or "", "created": (issue.get("createdAt") or "")[:10]}
    try:
        return template.format(**values)
    except (KeyError, IndexError) as exc:
        raise WizAPIError("--note-template uses an unknown placeholder: %s" % exc)


def alias_results(prefix, n, data, errors):
    """Per-alias outcome of a batched mutation: list of (ok, payload_or_error_text)."""
    by_alias, general = {}, []
    for e in errors:
        path = e.get("path") or []
        msg = "%s%s" % (e.get("message", ""), (" [%s]" % (e.get("extensions") or {}).get("code")) if (e.get("extensions") or {}).get("code") else "")
        if path and isinstance(path[0], str) and path[0].startswith(prefix):
            by_alias.setdefault(path[0], []).append(msg)
        else:
            general.append(msg)
    out = []
    for k in range(n):
        alias = "%s%d" % (prefix, k)
        errs = by_alias.get(alias, [])
        value = (data or {}).get(alias)
        if errs:
            out.append((False, "; ".join(errs)[:400]))
        elif value is None:
            out.append((False, ("; ".join(general) or "no result returned")[:400]))
        else:
            out.append((True, value))
    return out, general


def looks_like_batch_limit(messages):
    text = " ".join(messages).lower()
    return any(k in text for k in ("root field", "max_root", "batch", "too many", "complexity", "max_aliases", "height"))


def is_forbidden(text):
    return "forbidden" in text.lower() or "permission" in text.lower() or "not authorized" in text.lower()


class Journal(object):
    def __init__(self, path):
        self.path = path
        self.fh = open(path, "a", encoding="utf-8")

    def write(self, record):
        self.fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        self.fh.flush()
        try:
            os.fsync(self.fh.fileno())
        except OSError:
            pass

    def close(self):
        self.fh.close()


def read_journal(path):
    records = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except ValueError:
                    log.warning("Skipping an unreadable journal line")
    return records


# --------------------------------------------------------------------------- #
# Writes
# --------------------------------------------------------------------------- #

def add_comments(client, items, state):
    """items: list of dicts with issue_id and note. Sets item['comment'] = 'ok' | 'failed: ...'."""
    size = state["batch"]
    i = 0
    while i < len(items):
        batch = items[i:i + size]
        n = len(batch)
        q = "mutation StaleCleanupComment(%s) { %s }" % (
            ", ".join("$i%d: AddCommentInput!" % k for k in range(n)),
            " ".join("c%d: createCommentThreadComment(input: $i%d) { commentThread { id } }" % (k, k) for k in range(n)))
        variables = dict(("i%d" % k, {"subjectId": it["issue_id"], "subjectType": "ISSUE", "body": it["note"]}) for k, it in enumerate(batch))
        data, errors = client.mutate(q, variables)
        results, general = alias_results("c", n, data, errors)
        if n > 1 and not any(ok for ok, _ in results) and looks_like_batch_limit(general):
            log.warning("Batched mutation rejected (%s). Switching to one Issue per call.", "; ".join(general)[:160])
            state["batch"] = size = 1
            continue
        if not any(ok for ok, _ in results) and all(is_forbidden(t) for _, t in results):
            raise WizPermissionError("Adding comments is forbidden for this service account (needs write:comments). "
                                     "Nothing was changed in this batch. Detail: %s" % results[0][1])
        for it, (ok, payload) in zip(batch, results):
            it["comment"] = "ok" if ok else "failed: %s" % payload
        i += n


def update_status(client, items, state, patch_for):
    """items: list of dicts with issue_id. Sets item['update'] and item['new_status']."""
    size = state["batch"]
    i = 0
    while i < len(items):
        batch = items[i:i + size]
        n = len(batch)
        q = "mutation StaleCleanupStatus(%s) { %s }" % (
            ", ".join("$id%d: ID!, $p%d: UpdateIssuePatch" % (k, k) for k in range(n)),
            " ".join("u%d: updateIssue(input: {id: $id%d, patch: $p%d}) { issue { id status resolutionReason } }" % (k, k, k) for k in range(n)))
        variables = {}
        for k, it in enumerate(batch):
            variables["id%d" % k] = it["issue_id"]
            variables["p%d" % k] = patch_for(it, False)
        data, errors = client.mutate(q, variables)
        results, general = alias_results("u", n, data, errors)
        if n > 1 and not any(ok for ok, _ in results) and looks_like_batch_limit(general):
            log.warning("Batched mutation rejected (%s). Switching to one Issue per call.", "; ".join(general)[:160])
            state["batch"] = size = 1
            continue
        if not any(ok for ok, _ in results) and all(is_forbidden(t) for _, t in results):
            raise WizPermissionError("Changing Issue status is forbidden for this service account "
                                     "(needs write:issue_ignore and write:issue_status). Detail: %s" % results[0][1])
        for it, (ok, payload) in zip(batch, results):
            if ok:
                issue = (payload or {}).get("issue") or {}
                it["new_status"] = issue.get("status") or ""
                it["new_reason"] = issue.get("resolutionReason") or ""
                it["update"] = "ok" if it["new_status"] == it["target_status"] else "failed: status is %s after update" % (it["new_status"] or "unknown")
            elif state.get("patch_has_note") and "note" in str(payload).lower() and not it.get("_note_retry"):
                # Tenant requires a note on ignore and still accepts the legacy field: retry this one with it.
                it["_note_retry"] = True
                d2, e2 = client.mutate("mutation StaleCleanupStatusNote($id: ID!, $p: UpdateIssuePatch) { u0: updateIssue(input: {id: $id, patch: $p}) "
                                       "{ issue { id status resolutionReason } } }", {"id": it["issue_id"], "p": patch_for(it, True)})
                r2, _ = alias_results("u", 1, d2, e2)
                if r2[0][0]:
                    issue = (r2[0][1] or {}).get("issue") or {}
                    it["new_status"], it["new_reason"] = issue.get("status") or "", issue.get("resolutionReason") or ""
                    it["update"] = "ok" if it["new_status"] == it["target_status"] else "failed: status is %s after update" % it["new_status"]
                else:
                    it["update"] = "failed: %s" % r2[0][1]
            else:
                it["update"] = "failed: %s" % payload
        i += n


# --------------------------------------------------------------------------- #
# Plan
# --------------------------------------------------------------------------- #

def build_plan(client, args, now):
    controls = fetch_controls(client)
    disabled = [c for c in controls if c.get("enabled") is False]
    log.info("Disabled controls: %d of %d", len(disabled), len(controls))
    wanted = set(args.controls or [])
    unknown = wanted - {c["id"] for c in controls}
    if unknown:
        raise WizAPIError("--controls contains ids that are not in this tenant: %s" % ", ".join(sorted(unknown)))
    not_disabled = wanted - {c["id"] for c in disabled}
    if not_disabled:
        raise WizAPIError("--controls contains controls that are ENABLED, refusing to touch them: %s" % ", ".join(sorted(not_disabled)))
    plan, skipped = [], []
    for n, c in enumerate(disabled, 1):
        total = count_issues(client, c, args.statuses)
        if n % 50 == 0:
            log.info("Checked %d of %d disabled controls", n, len(disabled))
        if not total:
            continue
        entry = {"control": c, "api_total": total, "issues": [], "selected": (c["id"] in wanted) if wanted else True}
        log.info("Disabled control with open Issues: %s  %s  (%d)", c["id"], (c.get("name") or "")[:70], total)
        if not entry["selected"]:
            entry["skip_reason"] = "not in --controls"
            skipped.append(entry)
            continue
        issues, _ = fetch_issues(client, c, args.statuses)
        good, foreign = [], 0
        for iss in issues:
            if issue_belongs(iss, c):
                good.append(iss)
            else:
                foreign += 1
        if foreign:
            log.warning("  %d Issue(s) returned for %s do not name it as their source rule. Left out.", foreign, c["id"])
        entry["issues"], entry["foreign"] = good, foreign
        created = [parse_dt(i.get("createdAt")) for i in good]
        created = [d for d in created if d]
        entry["oldest"], entry["newest"] = (min(created) if created else None), (max(created) if created else None)
        entry["sev"] = Counter(i.get("severity") or "?" for i in good)
        entry["status"] = Counter(i.get("status") or "?" for i in good)
        if entry["newest"] and (now - entry["newest"]).days < args.stale_days and not args.include_recent:
            entry["selected"] = False
            entry["skip_reason"] = ("newest Issue is %d days old (under --stale-days %d): the control may not be dormant. "
                                    "Use --include-recent to override" % ((now - entry["newest"]).days, args.stale_days))
        (plan if entry["selected"] else skipped).append(entry)
    plan.sort(key=lambda e: -len(e["issues"]))
    skipped.sort(key=lambda e: -len(e["issues"]))
    return controls, plan, skipped


def issue_record(issue, control, note, target_status, reason):
    ent = issue.get("entitySnapshot") or {}
    return {
        "issue_id": issue.get("id"), "control_id": control.get("id"), "control_name": control.get("name"),
        "control_type": control.get("type"), "issue_type": issue.get("type"), "severity": issue.get("severity"),
        "prior_status": issue.get("status"), "created_at": issue.get("createdAt"),
        "entity_name": ent.get("name"), "entity_type": ent.get("nativeType") or ent.get("type"), "cloud": ent.get("cloudPlatform"),
        "account": ent.get("subscriptionName"), "account_id": ent.get("subscriptionExternalId"), "region": ent.get("region"),
        "projects": ", ".join(p.get("name") or "" for p in (issue.get("projects") or []) if isinstance(p, dict))[:300],
        "note": note, "target_status": target_status, "reason": reason,
        "comment": "", "update": "", "new_status": "", "new_reason": "", "result": "planned",
    }


# --------------------------------------------------------------------------- #
# Reports
# --------------------------------------------------------------------------- #

def summarize(records):
    per = OrderedDict()
    for r in records:
        e = per.setdefault(r["control_id"], {"control_id": r["control_id"], "control_name": r["control_name"], "control_type": r.get("control_type"),
                                             "planned": 0, "done": 0, "failed": 0, "not_attempted": 0, "sev": Counter(), "prior": Counter()})
        e["planned"] += 1
        e["sev"][r.get("severity") or "?"] += 1
        e["prior"][r.get("prior_status") or "?"] += 1
        if r["result"] == "done":
            e["done"] += 1
        elif r["result"] == "failed":
            e["failed"] += 1
        else:
            e["not_attempted"] += 1
    return per


def write_summary_txt(path, meta, per, skipped, remaining):
    lines = []
    lines.append("Wiz stale Issue cleanup - %s" % meta["mode_label"])
    lines.append("=" * 72)
    lines.append("Run started (UTC):   %s" % meta["started"])
    lines.append("Run finished (UTC):  %s" % meta["finished"])
    lines.append("Tenant id:           %s" % meta.get("tenant"))
    lines.append("API endpoint:        %s" % meta.get("api_url"))
    lines.append("Service account:     %s" % meta.get("sa_name"))
    lines.append("Script:              wiz_stale_issue_cleanup.py v%s" % VERSION)
    lines.append("Reference:           %s" % (meta.get("reference") or "none given"))
    if meta.get("aborted"):
        lines.append("RUN DID NOT COMPLETE:  %s" % meta["aborted"])
    lines.append("")
    lines.append("What was done")
    lines.append("-" * 72)
    lines.append(meta["action_text"])
    lines.append("")
    lines.append("Totals")
    lines.append("-" * 72)
    lines.append("Controls in scope:        %d" % len(per))
    lines.append("Issues in scope:          %d" % meta["planned"])
    if meta.get("plan_only"):
        lines.append("Changed in Wiz:           0 (plan only)")
    else:
        lines.append("%-25s %d" % (meta["done_label"] + ":", meta["done"]))
        lines.append("Failed:                   %d" % meta["failed"])
        lines.append("Not attempted:            %d" % meta["not_attempted"])
    lines.append("")
    lines.append("By disabled control")
    lines.append("-" * 72)
    for e in per.values():
        sev = ", ".join("%s %d" % (k, v) for k, v in e["sev"].most_common())
        lines.append("%s  %s" % (e["control_id"], e["control_name"]))
        if meta.get("plan_only"):
            lines.append("    in scope %d (no change made)" % e["planned"])
        else:
            lines.append("    in scope %d | %s %d | failed %d | not attempted %d%s" % (
                e["planned"], meta["done_label"].lower(), e["done"], e["failed"], e["not_attempted"],
                (" | still open after run %s" % remaining[e["control_id"]]) if e["control_id"] in remaining else ""))
        lines.append("    severity: %s" % sev)
    if skipped:
        lines.append("")
        lines.append("Disabled controls with open Issues that were NOT touched")
        lines.append("-" * 72)
        for s in skipped:
            lines.append("%s  %s  (%d open)  reason: %s" % (s["control"]["id"], s["control"].get("name"), len(s["issues"]) or s["api_total"], s.get("skip_reason", "not selected")))
    lines.append("")
    lines.append("Note added to each Issue (example from the first Issue)")
    lines.append("-" * 72)
    lines.append(meta.get("note_example") or "(none)")
    if meta.get("has_journal") and meta.get("done_label") == "Ignored":
        lines.append("")
        lines.append("How to reverse")
        lines.append("-" * 72)
        lines.append("python wiz_stale_issue_cleanup.py --revert %s --execute" % meta["journal"])
    text = "\n".join(lines) + "\n"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return text


def write_workbook(path, meta, records, per, skipped, remaining, app_url):
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Alignment, Font, PatternFill
        from openpyxl.utils import get_column_letter
    except ImportError:
        log.warning("openpyxl is not installed: skipping the workbook (pip install openpyxl). The journal and text summary are complete.")
        return False
    wb = Workbook()
    head_fill, head_font = PatternFill("solid", fgColor="1F3864"), Font(bold=True, color="FFFFFF")

    def header(ws, headers, widths):
        for c, h in enumerate(headers, 1):
            cell = ws.cell(row=1, column=c, value=h)
            cell.font, cell.fill = head_font, head_fill
            cell.alignment = Alignment(wrap_text=True, vertical="center")
            ws.column_dimensions[get_column_letter(c)].width = widths.get(h, 16)
        ws.freeze_panes = "A2"

    ws = wb.active
    ws.title = "Summary"
    rows = [
        ("Wiz stale Issue cleanup", meta["mode_label"]),
        ("Run started (UTC)", meta["started"]), ("Run finished (UTC)", meta["finished"]),
        ("Tenant id", meta.get("tenant")), ("API endpoint", meta.get("api_url")), ("Service account", meta.get("sa_name")),
        ("Script", "wiz_stale_issue_cleanup.py v%s" % VERSION), ("Reference", meta.get("reference") or "none given"),
        ("Run completed?", ("NO - " + meta["aborted"]) if meta.get("aborted") else "Yes"),
        ("", ""),
        ("What was done", meta["action_text"]),
        ("Why not 'Resolved'", "Wiz does not allow Graph Control or Cloud Configuration Issues to be resolved manually. Only Wiz resolves them during its scans. "
                               "Ignoring (status Rejected) is the only manual way to take them out of the open queue."),
        ("Side effect to know", "An ignored Issue stays ignored. If a control is re-enabled later, the same control and resource pairs stay silenced until reopened. "
                                "Use the journal with --revert to reopen them."),
        ("", ""),
        ("Controls in scope", len(per)), ("Issues in scope", meta["planned"]), (meta["done_label"], meta["done"]),
        ("Failed", meta["failed"]), ("Not attempted", meta["not_attempted"]),
        ("Statuses selected", ", ".join(meta["statuses"])), ("Staleness guard (days)", meta["stale_days"]),
        ("Read calls / write calls", "%s / %s" % (meta["read_calls"], meta["mutation_calls"])),
        ("", ""),
        ("Note added to each Issue (first Issue shown)", meta.get("note_example") or ""),
        ("Journal file", meta["journal"]),
        ("To reverse", ("python wiz_stale_issue_cleanup.py --revert %s --execute" % meta["journal"]) if meta.get("has_journal") else "n/a (nothing was changed)"),
    ]
    for i, (k, v) in enumerate(rows, 1):
        a = ws.cell(row=i, column=1, value=k)
        a.font = Font(bold=True)
        b = ws.cell(row=i, column=2, value=clean(v))
        b.alignment = Alignment(wrap_text=True, vertical="top")
    ws.column_dimensions["A"].width = 44
    ws.column_dimensions["B"].width = 120

    wc = wb.create_sheet("By Control")
    h = ["Control ID", "Control Name", "Control Type", "Issues In Scope", meta["done_label"], "Failed", "Not Attempted",
         "Still Open After Run", "Severity Mix", "Status Before"]
    header(wc, h, {"Control ID": 36, "Control Name": 70, "Severity Mix": 34, "Status Before": 28})
    for r, e in enumerate(per.values(), 2):
        vals = [e["control_id"], e["control_name"], e["control_type"], e["planned"], e["done"], e["failed"], e["not_attempted"],
                remaining.get(e["control_id"], ""), ", ".join("%s %d" % kv for kv in e["sev"].most_common()),
                ", ".join("%s %d" % kv for kv in e["prior"].most_common())]
        for c, v in enumerate(vals, 1):
            wc.cell(row=r, column=c, value=clean(v))
    tot = len(per) + 2
    wc.cell(row=tot, column=2, value="Total").font = Font(bold=True)
    for c, key in ((4, "planned"), (5, "done"), (6, "failed"), (7, "not_attempted")):
        wc.cell(row=tot, column=c, value=sum(e[key] for e in per.values())).font = Font(bold=True)

    wi = wb.create_sheet("Issues")
    h = ["Issue ID", "Result", "Control ID", "Control Name", "Severity", "Status Before", "Status After", "Reason After", "Comment",
         "Status Update", "Created At", "Resource Name", "Resource Type", "Cloud", "Account", "Account ID", "Region", "Projects",
         "Processed At (UTC)", "Issue Link", "Note"]
    header(wi, h, {"Issue ID": 38, "Control ID": 30, "Control Name": 50, "Resource Name": 40, "Resource Type": 22, "Account": 28,
                   "Projects": 34, "Comment": 20, "Status Update": 24, "Note": 80, "Issue Link": 18, "Processed At (UTC)": 22})
    for r, rec in enumerate(records[:1000000], 2):
        link = "%s/issues#~(issue~'%s)" % (app_url.rstrip("/"), rec["issue_id"])
        vals = [rec["issue_id"], rec["result"], rec["control_id"], rec["control_name"], rec["severity"], rec["prior_status"], rec.get("new_status"),
                rec.get("new_reason"), rec.get("comment"), rec.get("update"), rec["created_at"], rec["entity_name"], rec["entity_type"], rec["cloud"],
                rec["account"], rec["account_id"], rec["region"], rec["projects"], rec.get("processed_at"), link, rec["note"]]
        for c, v in enumerate(vals, 1):
            wi.cell(row=r, column=c, value=clean(v))
    wi.auto_filter.ref = "A1:%s%d" % (get_column_letter(len(h)), max(2, len(records) + 1))

    wsk = wb.create_sheet("Skipped Controls")
    h = ["Control ID", "Control Name", "Open Issues", "Newest Issue Created", "Why It Was Not Touched"]
    header(wsk, h, {"Control ID": 36, "Control Name": 70, "Why It Was Not Touched": 90, "Newest Issue Created": 24})
    for r, s in enumerate(skipped, 2):
        vals = [s["control"]["id"], s["control"].get("name"), len(s["issues"]) or s["api_total"],
                iso_z(s["newest"]) if s.get("newest") else "", s.get("skip_reason", "not selected")]
        for c, v in enumerate(vals, 1):
            wsk.cell(row=r, column=c, value=clean(v))
    wb.save(path)
    return True


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Ignore (close) Issues left open on disabled Wiz controls, with a note and a full log.",
                                formatter_class=argparse.RawDescriptionHelpFormatter, epilog=__doc__.split("Usage")[1] if "Usage" in __doc__ else "")
    p.add_argument("--execute", action="store_true", help="Make the changes. Without this the script only plans")
    p.add_argument("--controls", default=None, help="Comma-separated control ids to act on. Each must be disabled")
    p.add_argument("--all-disabled", action="store_true", help="Act on every disabled control that has open Issues")
    p.add_argument("--limit", type=int, default=0, help="Pilot: stop after this many Issues")
    p.add_argument("--reason", default="WONT_FIX", type=str.upper, choices=REASONS, help="Reason recorded on the ignored Issue (default WONT_FIX)")
    p.add_argument("--reference", default=None, help="Change record or ticket number to include in the note, e.g. CHG0012345")
    p.add_argument("--note-template", default=DEFAULT_NOTE, help="Note text. Placeholders: {control_name} {control_id} {date} {reference} {prior_status} {created}")
    p.add_argument("--statuses", default="OPEN,IN_PROGRESS", help="Issue statuses treated as still open (default OPEN,IN_PROGRESS)")
    p.add_argument("--stale-days", type=int, default=30, help="Skip a disabled control whose newest Issue is younger than this (default 30)")
    p.add_argument("--include-recent", action="store_true", help="Do not apply the --stale-days guard")
    p.add_argument("--revert", default=None, metavar="JOURNAL", help="Reopen the Issues ignored in the run that wrote this journal")
    p.add_argument("--resume", default=None, metavar="JOURNAL", help="Continue an interrupted run: Issues already commented in this journal are not commented again")
    p.add_argument("--yes", action="store_true", help="Skip the typed confirmation (for unattended runs)")
    p.add_argument("--batch-size", type=int, default=10, help="Issues per write call, 1 to 10 (default 10)")
    p.add_argument("--calls-per-second", type=float, default=1.0, help="Write calls per second (default 1.0). The tenant-wide pool for all service accounts is 3")
    p.add_argument("-o", "--output", default=None, help="Output prefix (default Wiz_Stale_Issue_Cleanup_<UTC timestamp>)")
    p.add_argument("--app-url", default=os.environ.get("WIZ_APP_URL", DEFAULT_APP_URL))
    p.add_argument("--auth-url", default=os.environ.get("WIZ_AUTH_URL", DEFAULT_AUTH_URL))
    p.add_argument("--audience", default=os.environ.get("WIZ_AUDIENCE", "wiz-api"))
    p.add_argument("--ca-bundle", default=None, help="Corporate CA bundle path for TLS verification")
    p.add_argument("-v", "--verbose", action="store_true")
    args = p.parse_args(argv)
    args.controls = [c.strip() for c in args.controls.split(",") if c.strip()] if args.controls else []
    args.statuses = [s.strip().upper() for s in args.statuses.split(",") if s.strip()]
    args.batch_size = max(1, min(MAX_ROOT_FIELDS, args.batch_size))
    if args.execute and not args.revert and not args.controls and not args.all_disabled:
        p.error("--execute needs --controls <ids> or --all-disabled")
    if "REJECTED" in args.statuses or "RESOLVED" in args.statuses:
        p.error("--statuses may only contain OPEN and IN_PROGRESS")
    return args


def confirm(args, phrase, prompt):
    if args.yes:
        return True
    if not sys.stdin.isatty():
        log.error("Not an interactive terminal. Re-run with --yes to confirm.")
        return False
    print("")
    print(prompt)
    typed = input("Type  %s  to continue: " % phrase).strip()
    return typed == phrase


def run_writes(client, records, state, journal, args, patch_for, commented_before, now, label):
    done = failed = 0
    total = len(records)
    for start in range(0, total, state["batch"] if state["batch"] > 0 else 1):
        batch = records[start:start + state["batch"]]
        if not batch:
            break
        need_comment = [r for r in batch if r["issue_id"] not in commented_before]
        for r in batch:
            if r["issue_id"] in commented_before:
                r["comment"] = "ok (earlier run)"
        if need_comment:
            add_comments(client, need_comment, state)
        to_update = [r for r in batch if r["comment"].startswith("ok")]
        if to_update:
            update_status(client, to_update, state, patch_for)
        stamp = iso_z(datetime.now(timezone.utc))
        for r in batch:
            r["processed_at"] = stamp
            if not r["comment"].startswith("ok"):
                r["update"] = "not attempted: comment failed"
                r["result"] = "failed"
            elif r["update"] == "ok":
                r["result"] = "done"
            else:
                r["result"] = "failed"
            done += r["result"] == "done"
            failed += r["result"] == "failed"
            journal.write(dict((k, v) for k, v in r.items() if not k.startswith("_")))
        processed = min(total, start + len(batch))
        if processed % 500 < len(batch) or processed == total:
            log.info("%s: %d of %d processed (%d done, %d failed)", label, processed, total, done, failed)
    return done, failed


def safe_writes(client, records, state, journal, args, patch_for, commented_before, now, label, meta, journal_path):
    """Run the writes. If the run stops early, keep what was done so the reports are still written."""
    try:
        run_writes(client, records, state, journal, args, patch_for, commented_before, now, label)
    except KeyboardInterrupt:
        meta["aborted"] = "Interrupted by the operator. Continue with --resume %s" % journal_path
    except WizAPIError as exc:
        meta["aborted"] = "Stopped early: %s" % str(exc)[:400]
    if meta.get("aborted"):
        log.error(meta["aborted"])


def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO, format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")
    client_id, client_secret = os.environ.get("WIZ_CLIENT_ID"), os.environ.get("WIZ_CLIENT_SECRET")
    if not client_id and sys.stdin.isatty():
        client_id = input("WIZ_CLIENT_ID: ").strip()
    if not client_secret and sys.stdin.isatty():
        client_secret = getpass.getpass("WIZ_CLIENT_SECRET: ")
    if not client_id or not client_secret:
        log.error("WIZ_CLIENT_ID and WIZ_CLIENT_SECRET must be set in the environment")
        return 1
    now = datetime.now(timezone.utc)
    prefix = args.output or "Wiz_Stale_Issue_Cleanup_%s" % now.strftime("%Y%m%d_%H%M%S")
    if prefix.lower().endswith(".xlsx"):
        prefix = prefix[:-5]
    journal_path = prefix + "_journal.jsonl"
    client = WizClient(args.auth_url, os.environ.get("WIZ_API_URL"), client_id, client_secret, audience=args.audience,
                       verify=args.ca_bundle or True, mutation_cps=args.calls_per_second)
    journal = None
    try:
        client.ensure_api_url()
        _ = client.token
        tenant, sa_name = client.token_claims.get("tid"), client.token_claims.get("name")
        log.info("Tenant %s, service account %s, endpoint %s", tenant, sa_name, client.api_url)
        schema = probe_schema(client)
        state = {"batch": args.batch_size, "patch_has_note": schema.get("patch_has_note")}
        meta = {"started": iso_z(now), "tenant": tenant, "sa_name": sa_name, "api_url": client.api_url, "reference": args.reference,
                "statuses": args.statuses, "stale_days": "off" if args.include_recent else args.stale_days, "journal": os.path.basename(journal_path)}

        # ------------------------------------------------------------------ revert
        if args.revert:
            prior = read_journal(args.revert)
            targets = OrderedDict()
            for r in prior:
                if r.get("result") == "done" and r.get("target_status") == "REJECTED":
                    targets[r["issue_id"]] = r
            records = []
            for r in targets.values():
                rec = dict(r)
                rec.update({"prior_status": "REJECTED", "target_status": r.get("prior_status") or "OPEN", "reason": "",
                            "note": REVERT_NOTE.format(date=now.strftime("%Y-%m-%d"), ignored_on=(r.get("processed_at") or "")[:10],
                                                       reference=(" Reference: %s." % args.reference) if args.reference else ""),
                            "comment": "", "update": "", "new_status": "", "new_reason": "", "result": "planned"})
                records.append(rec)
            if args.limit:
                records = records[:args.limit]
            log.info("Revert: %d Issues were ignored in %s", len(records), args.revert)
            meta.update({"mode_label": "REVERT - %s" % ("EXECUTED" if args.execute else "PLAN ONLY, nothing changed"), "done_label": "Reopened",
                         "action_text": "Reopened Issues that the earlier cleanup run had ignored, restoring the status each had before, and added a comment saying so."
                         if args.execute else "Plan only. Lists the Issues that would be reopened. Nothing was changed."})
            if args.execute and records:
                if not confirm(args, "REOPEN %d" % len(records), "About to REOPEN %d Issues in tenant %s." % (len(records), tenant)):
                    log.error("Confirmation did not match. Nothing was changed.")
                    return 1
                journal = Journal(journal_path)
                safe_writes(client, records, state, journal, args, lambda it, with_note: {"status": it["target_status"]}, set(), now, "Reopen", meta, journal_path)
            return finish(prefix, journal_path, meta, records, [], {}, client, args)

        # ------------------------------------------------------------------ plan
        if not schema.get("comment_mutation", True):
            log.warning("createCommentThreadComment is not in this tenant's schema. The note cannot be added as a comment.")
        controls, plan, skipped = build_plan(client, args, now)
        records = []
        for entry in plan:
            for iss in entry["issues"]:
                note = render_note(args.note_template, entry["control"], iss, args, now)
                records.append(issue_record(iss, entry["control"], note, "REJECTED", args.reason))
        full_count = len(records)
        if args.limit and len(records) > args.limit:
            log.info("--limit %d: acting on the first %d of %d Issues", args.limit, args.limit, len(records))
            records = records[:args.limit]
        meta["note_example"] = records[0]["note"] if records else ""
        log.info("Plan: %d disabled control(s) in scope, %d Issue(s). %d disabled control(s) with open Issues left out.", len(plan), full_count, len(skipped))
        for entry in plan:
            log.info("  %-14s %6d  %s", entry["control"]["id"][-14:], len(entry["issues"]), (entry["control"].get("name") or "")[:80])

        if not args.execute:
            meta.update({"mode_label": "PLAN ONLY, nothing changed", "done_label": "Ignored",
                         "action_text": "Plan only. Lists the open Issues on disabled controls that would be set to Ignored (status Rejected, reason %s) "
                                        "with the note below. Nothing was changed in Wiz." % args.reason})
            return finish(prefix, journal_path, meta, records, skipped, {}, client, args)

        if not records:
            log.info("Nothing to do.")
            meta.update({"mode_label": "EXECUTE - nothing to do", "done_label": "Ignored", "action_text": "No open Issues were found on the selected disabled controls."})
            return finish(prefix, journal_path, meta, records, skipped, {}, client, args)
        if not schema.get("comment_mutation", True):
            raise WizAPIError("Cannot add the note: createCommentThreadComment is not available on this tenant. Nothing was changed.")

        prompt = ("About to set %d Issues to IGNORED (status Rejected, reason %s) on %d disabled control(s) in tenant %s,\n"
                  "adding a comment to each. Ignored Issues leave the open queue. This can be reversed with --revert and the journal.\n"
                  "Check first that no Automation Rule fires when an Issue is ignored, or it will fire once per Issue."
                  % (len(records), args.reason, len({r["control_id"] for r in records}), tenant))
        if not confirm(args, "IGNORE %d" % len(records), prompt):
            log.error("Confirmation did not match. Nothing was changed.")
            return 1

        commented_before = set()
        if args.resume:
            for r in read_journal(args.resume):
                if str(r.get("comment", "")).startswith("ok"):
                    commented_before.add(r["issue_id"])
            log.info("Resume: %d Issues already have the comment from the earlier run", len(commented_before))

        # Re-check, right before writing, that every control in scope is still disabled.
        fresh = dict((c["id"], c) for c in fetch_controls(client))
        still = [cid for cid in {r["control_id"] for r in records} if (fresh.get(cid) or {}).get("enabled") is not False]
        if still:
            raise WizAPIError("These controls are no longer disabled, refusing to continue: %s" % ", ".join(sorted(still)))

        journal = Journal(journal_path)
        journal.write({"_run": "start", "ts": iso_z(datetime.now(timezone.utc)), "tenant": tenant, "service_account": sa_name,
                       "planned": len(records), "reason": args.reason, "reference": args.reference, "version": VERSION})

        def patch_for(it, with_note):
            patch = {"status": "REJECTED", "resolutionReason": it["reason"]}
            if with_note:
                patch["note"] = it["note"]
            return patch

        safe_writes(client, records, state, journal, args, patch_for, commented_before, now, "Ignore", meta, journal_path)
        remaining = {}
        for entry in plan:
            try:
                remaining[entry["control"]["id"]] = count_issues(client, entry["control"], args.statuses)
            except WizAPIError as exc:
                remaining[entry["control"]["id"]] = "count failed: %s" % str(exc)[:80]
        meta.update({"mode_label": "EXECUTED%s" % (" (pilot, --limit %d)" % args.limit if args.limit else ""), "done_label": "Ignored",
                     "action_text": "Open Issues on disabled controls were set to Ignored (status Rejected, reason %s). A comment explaining that the Issue "
                                    "is stale was added to each Issue before its status was changed." % args.reason})
        return finish(prefix, journal_path, meta, records, skipped, remaining, client, args)
    except WizPermissionError as exc:
        log.error("Permission error: %s", exc)
        return 1
    except WizAPIError as exc:
        log.error("%s", exc)
        return 1
    except KeyboardInterrupt:
        log.error("Interrupted. Everything processed so far is in %s. Re-run with --resume %s to continue.", journal_path, journal_path)
        return 1
    finally:
        if journal:
            journal.close()


def finish(prefix, journal_path, meta, records, skipped, remaining, client, args):
    per = summarize(records)
    meta["finished"] = iso_z(datetime.now(timezone.utc))
    meta["planned"] = len(records)
    meta["done"] = sum(1 for r in records if r["result"] == "done")
    meta["failed"] = sum(1 for r in records if r["result"] == "failed")
    meta["not_attempted"] = sum(1 for r in records if r["result"] not in ("done", "failed"))
    meta["read_calls"], meta["mutation_calls"] = client.read_calls, client.mutation_calls
    meta["has_journal"] = os.path.exists(journal_path)
    meta["plan_only"] = not args.execute
    if not meta["has_journal"]:
        meta["journal"] = "(none written: no changes were made)"
    text = write_summary_txt(prefix + "_summary.txt", meta, per, skipped, remaining)
    wrote = write_workbook(prefix + ".xlsx", meta, records, per, skipped, remaining, args.app_url)
    print("")
    print(text)
    log.info("Written: %s%s", prefix + "_summary.txt", (", " + prefix + ".xlsx") if wrote else "")
    if os.path.exists(journal_path):
        log.info("Journal: %s (keep this file: it is the record of what changed and the input for --revert)", journal_path)
    if meta.get("aborted"):
        return 1
    return 2 if meta["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
