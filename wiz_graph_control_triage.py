#!/usr/bin/env python3
"""
Wiz Graph Control Triage Exporter
=================================

Exports every Graph Control in a Wiz tenant together with the Issues it has
generated, and writes a triage workbook with two review levels:

  * Controls Review  - one row per Graph Control: Wiz metadata, the graph inputs
                       the control correlates (parsed from the control's query),
                       Issue statistics (open / in-progress / resolved / rejected,
                       resolution-reason mix, reject and false-positive rates,
                       projects, clouds, age) and blank triage columns with
                       drop-downs for the applicability decision.
  * Issues           - one row per Issue (all, or a per-control sample) with the
                       entity, project, status, age, ticket, deep links and blank
                       triage columns for the true/false-positive verdict.
  * Analysis         - where the fix belongs, by Issue volume: share of open Issues
                       carried by config rules acting as controls, graph controls
                       built on CCR findings, other finding types, and control-level
                       logic; concentration (top 10/20/50); top controls; an audit of
                       every entity type seen in control queries.
  * Control Inputs   - one row per (control, input entity type) so you can pivot
                       on which underlying finding types drive the Issue volume.
  * Summary / README / Lists - run evidence (filters, totalCounts, pruned
                       fields), triage guidance, drop-down sources.

Data sources (GraphQL):
  controls                 read:controls                 (non-WIN root: introspected + pruned)
  issuesV2                 read:issues                   (WIN root, schema-stable)
  cloudConfigurationRules  read:cloud_configuration_rule (optional, resolves CCR ids referenced
                                                          by control queries to short IDs)

Authentication (OAuth2 client credentials, secrets only via environment):
  WIZ_CLIENT_ID, WIZ_CLIENT_SECRET            required (prompted if missing and a TTY)
  WIZ_API_URL   https://api.<dc>.app.wiz.io/graphql  optional - derived from the token's `dc` claim
  WIZ_AUTH_URL  default https://auth.app.wiz.io/oauth/token (FedRAMP https://auth.app.wiz.us/oauth/token,
                GovCloud https://auth.gov.wiz.io/oauth/token)
  WIZ_AUDIENCE  default wiz-api (legacy Auth0 tenants: beyond-api)

Usage:
  python3 wiz_graph_control_triage.py --dry-run -v          # connectivity, schema, counts only
  python3 wiz_graph_control_triage.py                       # full export + analysis -> Wiz_Graph_Control_Triage_<date>.xlsx
  python3 wiz_graph_control_triage.py --org "S&P" -o spg_gc_triage.xlsx
  python3 wiz_graph_control_triage.py --exclude-config-controls   # graph (toxic combination) controls only, as in v1.0.0
  python3 wiz_graph_control_triage.py --statuses OPEN,IN_PROGRESS --severity CRITICAL,HIGH --project <projectId>

Exit codes: 0 success, 2 partial (an optional data source was unavailable), 1 fatal.
Dependencies: requests, openpyxl   (pip install requests openpyxl)
"""

import argparse
import base64
import getpass
import json
import logging
import os
import random
import re
import statistics
import sys
import time
from collections import Counter, OrderedDict, defaultdict
from datetime import datetime, timedelta, timezone

try:
    import requests
except ImportError:  # pragma: no cover
    sys.stderr.write("ERROR: the 'requests' package is required. Install with: pip install requests\n")
    sys.exit(1)

VERSION = "1.1.0"
# 1.0.0 (2026-11-09): initial release.
# 1.1.0 (2026-11-12): after the first live run (DC us25). Config rules acting as controls and their
#   CLOUD_CONFIGURATION Issues are pulled by default; every control gets a Fix Location; new Analysis sheet
#   (share of open Issues by fix location and input class, concentration, top controls, entity-type audit);
#   history window default 180 days; headline numbers printed at the end of the run.
USER_AGENT = "wiz-graph-control-triage/%s" % VERSION
DEFAULT_AUTH_URL = "https://auth.app.wiz.io/oauth/token"
DEFAULT_APP_URL = "https://app.wiz.io"
MAX_CELL_CHARS = 32000
MAX_PAGES = 10000
ILLEGAL_XLSX_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")
FIELD_ERR_RE = re.compile(r'Cannot query field "([^"]+)" on type "([^"]+)"')
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

log = logging.getLogger("wiz-gc-triage")


# --------------------------------------------------------------------------- #
# API client (same contract as the other scripts in the wiz-expert bundle)
# --------------------------------------------------------------------------- #

class WizAPIError(Exception):
    """Fatal or non-retryable API error."""


class WizPermissionError(WizAPIError):
    """Service account lacks the scope for this query."""


class GraphQLFieldError(WizAPIError):
    """Schema validation error naming unknown fields. Carries (field, parent_type) pairs."""

    def __init__(self, message, bad_fields):
        super().__init__(message)
        self.bad_fields = bad_fields


class WizClient:
    def __init__(self, auth_url, api_url, client_id, client_secret, audience="wiz-api",
                 timeout=110, max_retries=5, verify=True, pause=0.25):
        self.auth_url = auth_url
        self.api_url = api_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.audience = audience
        self.timeout = timeout
        self.max_retries = max_retries
        self.pause = pause
        self.session = requests.Session()
        self.session.verify = verify
        self.session.headers.update({"User-Agent": USER_AGENT})
        self._token = None
        self._token_exp = 0.0
        self.requests_made = 0
        self.token_claims = {}

    # -- auth ---------------------------------------------------------------- #
    def _fetch_token(self):
        log.debug("Requesting OAuth token from %s (audience=%s)", self.auth_url, self.audience)
        resp = self.session.post(
            self.auth_url,
            data={"grant_type": "client_credentials", "client_id": self.client_id,
                  "client_secret": self.client_secret, "audience": self.audience},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=self.timeout,
        )
        if resp.status_code != 200:
            body = resp.text[:500]
            hint = " (legacy Auth0 tenants use --audience beyond-api)" if "audience" in body.lower() else ""
            raise WizAPIError("Token request failed: HTTP %s from %s%s\n%s" % (resp.status_code, self.auth_url, hint, body))
        data = resp.json()
        self._token = data["access_token"]
        expires_in = int(data.get("expires_in", 86400))
        self._token_exp = time.time() + max(60, expires_in - 300)
        self.token_claims = decode_jwt_payload(self._token)
        log.debug("Token acquired (expires_in=%ss, dc=%s)", expires_in, self.token_claims.get("dc"))

    @property
    def token(self):
        if not self._token or time.time() >= self._token_exp:
            self._fetch_token()
        return self._token

    def ensure_api_url(self):
        """Derive https://api.<dc>.app.wiz.io/graphql from the JWT `dc` claim when WIZ_API_URL is unset."""
        if self.api_url:
            return self.api_url
        _ = self.token
        dc = self.token_claims.get("dc")
        if not dc:
            raise WizAPIError("WIZ_API_URL is not set and the token carries no `dc` claim - copy the API Endpoint URL from the Wiz console")
        host = "app.wiz.io"
        if "wiz.us" in self.auth_url:
            host = "app.wiz.us"
        elif "gov.wiz.io" in self.auth_url:
            host = "gov.wiz.io"
        self.api_url = "https://api.%s.%s/graphql" % (dc, host)
        log.info("WIZ_API_URL derived from token dc claim: %s", self.api_url)
        return self.api_url

    # -- graphql ------------------------------------------------------------- #
    @staticmethod
    def _retry_after_seconds(resp):
        ra = resp.headers.get("Retry-After")
        if not ra:
            return None
        try:
            return min(60, max(1, int(ra)))
        except ValueError:
            try:
                from email.utils import parsedate_to_datetime
                return min(60, max(1, int(parsedate_to_datetime(ra).timestamp() - time.time())))
            except Exception:
                return None

    def graphql(self, query, variables=None):
        attempt = 0
        refreshed_once = False
        while True:
            attempt += 1
            try:
                resp = self.session.post(
                    self.api_url,
                    json={"query": query, "variables": variables or {}},
                    headers={"Authorization": "Bearer %s" % self.token, "Content-Type": "application/json"},
                    timeout=self.timeout,
                )
                self.requests_made += 1
            except requests.RequestException as exc:
                if attempt <= self.max_retries:
                    delay = min(30, 0.5 * (2 ** attempt)) + random.uniform(0, 0.5)
                    log.warning("Network error (%s); retry %d/%d in %.1fs", exc.__class__.__name__, attempt, self.max_retries, delay)
                    time.sleep(delay)
                    continue
                raise WizAPIError("Network error after %d retries: %s" % (self.max_retries, exc))

            if resp.status_code == 401 and not refreshed_once:
                log.info("HTTP 401 - refreshing token and retrying once (a persistent 401 usually means the wrong data-center URL)")
                self._token = None
                refreshed_once = True
                continue
            if resp.status_code == 429:
                delay = self._retry_after_seconds(resp) or (min(30, 0.5 * (2 ** attempt)) + random.uniform(0, 1))
                if attempt <= self.max_retries + 3:
                    log.warning("HTTP 429 rate limited; sleeping %.1fs (attempt %d)", delay, attempt)
                    time.sleep(delay)
                    continue
                raise WizAPIError("Rate limited: gave up after %d attempts" % attempt)
            if resp.status_code >= 500:
                if attempt <= self.max_retries:
                    delay = min(30, 0.5 * (2 ** attempt)) + random.uniform(0, 0.5)
                    log.warning("HTTP %s; retry %d/%d in %.1fs", resp.status_code, attempt, self.max_retries, delay)
                    time.sleep(delay)
                    continue
                raise WizAPIError("HTTP %s after %d retries: %s" % (resp.status_code, self.max_retries, resp.text[:300]))
            if resp.status_code == 401:
                raise WizAPIError("HTTP 401 UNAUTHORIZED with a fresh token - check WIZ_API_URL points at this tenant's data center (%s)" % self.api_url)
            if resp.status_code not in (200, 400):
                raise WizAPIError("HTTP %s: %s" % (resp.status_code, resp.text[:500]))

            try:
                payload = resp.json()
            except ValueError:
                raise WizAPIError("Non-JSON response: %s" % resp.text[:300])

            errors = payload.get("errors") or []
            if errors:
                messages = "; ".join(str(e.get("message", "")) for e in errors)[:1500]
                codes = {(e.get("extensions") or {}).get("code") for e in errors}
                if "RATE_LIMIT_EXCEEDED" in codes and attempt <= self.max_retries + 3:
                    delay = min(30, 0.5 * (2 ** attempt)) + random.uniform(0, 1)
                    log.warning("GraphQL RATE_LIMIT_EXCEEDED; sleeping %.1fs", delay)
                    time.sleep(delay)
                    continue
                if "UNAUTHENTICATED" in codes and not refreshed_once:
                    self._token = None
                    refreshed_once = True
                    continue
                bad = FIELD_ERR_RE.findall(messages)
                if bad:
                    raise GraphQLFieldError(messages, bad)
                if "FORBIDDEN" in codes or "FORBIDDEN_IP" in codes:
                    raise WizPermissionError(messages)
                if payload.get("data"):
                    log.warning("Partial GraphQL errors (continuing): %s", messages)
                    if self.pause:
                        time.sleep(self.pause)
                    return payload["data"]
                raise WizAPIError("GraphQL error: %s" % messages)
            if self.pause:
                time.sleep(self.pause)
            return payload.get("data") or {}


def decode_jwt_payload(token):
    try:
        part = token.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part.encode()).decode())
    except Exception:
        return {}


# --------------------------------------------------------------------------- #
# Schema introspection
# --------------------------------------------------------------------------- #

TYPE_REF = "kind name ofType { kind name ofType { kind name ofType { kind name ofType { kind name } } } }"


def unwrap_type(tref):
    while tref and tref.get("kind") in ("NON_NULL", "LIST"):
        tref = tref.get("ofType")
    if not tref:
        return (None, None)
    return (tref.get("kind"), tref.get("name"))


class SchemaExplorer:
    def __init__(self, client, enabled=True):
        self.client = client
        self.enabled = enabled
        self.available = None
        self._root = {}
        self._type_fields = {}
        self._input_fields = {}
        self._enums = {}

    def probe(self):
        if not self.enabled:
            self.available = False
            return False
        if self.available is not None:
            return self.available
        q = "query { __schema { queryType { fields { name type { %s } } } } }" % TYPE_REF
        try:
            data = self.client.graphql(q)
            self._root = {f["name"]: f["type"] for f in data["__schema"]["queryType"]["fields"]}
            self.available = True
            log.info("Schema introspection available: %d root queries visible", len(self._root))
        except (WizAPIError, KeyError, TypeError) as exc:
            self.available = False
            log.warning("Schema introspection unavailable (%s) - using error-driven field pruning", str(exc)[:200])
        return self.available

    def has_root(self, name):
        return (name in self._root) if self.available else True

    def type_fields(self, type_name):
        if type_name in self._type_fields:
            return self._type_fields[type_name]
        q = 'query { __type(name: "%s") { fields { name type { %s } } } }' % (type_name, TYPE_REF)
        try:
            data = self.client.graphql(q)
            fields = (data.get("__type") or {}).get("fields") or []
            result = {f["name"]: f["type"] for f in fields}
        except WizAPIError:
            result = {}
        self._type_fields[type_name] = result
        return result

    def input_fields(self, type_name):
        if type_name in self._input_fields:
            return self._input_fields[type_name]
        q = 'query { __type(name: "%s") { inputFields { name type { %s } } } }' % (type_name, TYPE_REF)
        try:
            data = self.client.graphql(q)
            fields = (data.get("__type") or {}).get("inputFields") or []
            result = {f["name"]: f["type"] for f in fields}
        except WizAPIError:
            result = {}
        self._input_fields[type_name] = result
        return result

    def enum_values(self, type_name):
        if type_name in self._enums:
            return self._enums[type_name]
        try:
            data = self.client.graphql('query { __type(name: "%s") { enumValues { name } } }' % type_name)
            vals = [v["name"] for v in (data.get("__type") or {}).get("enumValues") or []]
        except WizAPIError:
            vals = []
        self._enums[type_name] = vals
        return vals

    def node_type_of(self, root_name):
        tref = self._root.get(root_name)
        if not tref:
            return None
        _, conn = unwrap_type(tref)
        if not conn:
            return None
        cfields = self.type_fields(conn)
        nodes = cfields.get("nodes") or cfields.get("edges")
        if not nodes:
            return None
        _, node_t = unwrap_type(nodes)
        if node_t and node_t.lower().endswith("edge"):
            efields = self.type_fields(node_t)
            if "node" in efields:
                _, node_t = unwrap_type(efields["node"])
        return node_t

    def prune_spec(self, type_name, spec, pruned_log=None, path=""):
        """Keep only the fields of `spec` that exist on `type_name` (recursively). Inline fragments pass through."""
        available = self.type_fields(type_name)
        if not available:
            return OrderedDict(spec)
        out = OrderedDict()
        for fname, sub in spec.items():
            if fname.startswith("...") or fname == "__typename":
                out[fname] = sub
                continue
            if fname not in available:
                if pruned_log is not None:
                    pruned_log.append("%s%s (not in %s)" % (path, fname, type_name))
                continue
            kind, base = unwrap_type(available[fname])
            if kind in ("OBJECT", "INTERFACE"):
                pruned = self.prune_spec(base, sub or OrderedDict([("id", None)]), pruned_log, path + fname + ".")
                if pruned:
                    out[fname] = pruned
            elif kind in ("SCALAR", "ENUM"):
                out[fname] = None
            elif kind == "UNION":
                out[fname] = sub   # fragments inside - validated by the server
        return out


# --------------------------------------------------------------------------- #
# Selection specs
# --------------------------------------------------------------------------- #

SUBCATS = OrderedDict([("id", None), ("title", None),
                       ("category", OrderedDict([("id", None), ("name", None),
                                                 ("framework", OrderedDict([("id", None), ("name", None)]))]))])

# Fields confirmed in Wiz's own Postman collection (ManageControlsTable) plus LIKELY extras; all pruned live.
CONTROL_SPEC = OrderedDict([
    ("id", None), ("name", None), ("description", None), ("type", None), ("severity", None),
    ("enabled", None), ("query", None), ("scopeQuery", None),
    ("enabledForLBI", None), ("enabledForMBI", None), ("enabledForHBI", None), ("enabledForUnattributed", None),
    ("resolutionRecommendation", None), ("risks", None), ("tags", None),
    ("supportsNRT", None), ("hasAutoRemediation", None),
    ("lastRunAt", None), ("lastSuccessfulRunAt", None), ("lastRunError", None),
    ("createdAt", None), ("updatedAt", None),
    ("scopeProject", OrderedDict([("id", None), ("name", None)])),
    ("sourceCloudConfigurationRule", OrderedDict([("id", None), ("name", None), ("shortId", None)])),
    ("createdBy", OrderedDict([("id", None), ("name", None), ("email", None)])),
    ("securitySubCategories", SUBCATS),
])

# issuesV2 node selection (WIN API, docs.wiz.io/dev/issues-query). `notes` deliberately absent (removed 2026-11-16).
ISSUE_SPEC = OrderedDict([
    ("id", None), ("type", None), ("severity", None), ("status", None),
    ("createdAt", None), ("updatedAt", None), ("resolvedAt", None), ("statusChangedAt", None),
    ("dueAt", None), ("resolutionReason", None),
    ("sourceRules", OrderedDict([
        ("__typename", None),
        ("... on Control", OrderedDict([("id", None), ("name", None)])),
        ("... on CloudConfigurationRule", OrderedDict([("id", None), ("name", None),
                                                      ("control", OrderedDict([("id", None), ("name", None)]))])),
        ("... on CloudEventRule", OrderedDict([("id", None), ("name", None)])),
    ])),
    ("entitySnapshot", OrderedDict([
        ("id", None), ("type", None), ("nativeType", None), ("name", None), ("status", None),
        ("cloudPlatform", None), ("cloudProviderURL", None), ("region", None),
        ("subscriptionExternalId", None), ("subscriptionName", None), ("providerId", None),
        ("externalId", None), ("tags", None), ("createdAt", None),
    ])),
    ("projects", OrderedDict([("id", None), ("name", None), ("slug", None), ("businessUnit", None),
                              ("riskProfile", OrderedDict([("businessImpact", None)]))])),
    ("serviceTickets", OrderedDict([("externalId", None), ("name", None), ("url", None)])),
])

CCR_SPEC = OrderedDict([("id", None), ("shortId", None), ("name", None), ("enabled", None),
                        ("severity", None), ("builtin", None), ("functionAsControl", None),
                        ("cloudProvider", None)])


def build_selection(spec):
    parts = []
    for fname, sub in spec.items():
        if sub:
            parts.append("%s { %s }" % (fname, build_selection(sub)))
        else:
            parts.append(fname)
    return " ".join(parts)


def remove_fields(spec, names):
    removed = 0
    for name in list(spec.keys()):
        if name in names:
            del spec[name]
            removed += 1
        elif isinstance(spec.get(name), dict):
            removed += remove_fields(spec[name], names)
            if not spec[name]:
                del spec[name]
    return removed


# --------------------------------------------------------------------------- #
# Generic paginated fetch with error-driven pruning
# --------------------------------------------------------------------------- #

def paged_fetch(client, root, spec, page_size, label, pruned_log, filter_by=None, filter_type=None,
                extra_selection="", extra_vars=None, extra_var_decl="", order_by=None, order_type=None,
                max_pages=MAX_PAGES):
    """Relay-style pagination over `root`. Returns (nodes, total_count, meta)."""
    nodes, after, page, size, total = [], None, 0, page_size, None
    rounds = 0
    use_edges = False
    include_total = True
    var_decl = "$first: Int, $after: String"
    if filter_type:
        var_decl += ", $filterBy: %s" % filter_type
    if order_type and order_by is not None:
        var_decl += ", $orderBy: %s" % order_type
    var_decl += extra_var_decl
    meta = {"pages": 0, "selection": None, "filter": filter_by}
    while True:
        args = "first: $first, after: $after"
        if filter_type:
            args += ", filterBy: $filterBy"
        if order_type and order_by is not None:
            args += ", orderBy: $orderBy"
        selection = build_selection(spec) + (" " + extra_selection if extra_selection else "")
        body = ("edges { node { %s } }" % selection) if use_edges else ("nodes { %s }" % selection)
        query = "query Q(%s) { %s(%s) { %s pageInfo { hasNextPage endCursor } %s } }" % (
            var_decl, root, args, body, "totalCount" if include_total else "")
        variables = {"first": size, "after": after}
        if filter_type:
            variables["filterBy"] = filter_by or {}
        if order_type and order_by is not None:
            variables["orderBy"] = order_by
        if extra_vars:
            variables.update(extra_vars)
        meta["selection"] = selection
        try:
            data = client.graphql(query, variables)
        except GraphQLFieldError as exc:
            bad = {f for f, _ in exc.bad_fields}
            rounds += 1
            if "totalCount" in bad and include_total:
                include_total = False
                continue
            if "nodes" in bad and not use_edges:
                use_edges = True
                continue
            if extra_selection and any(b in extra_selection for b in bad):
                log.info("[%s] dropping extra selection (%s)", label, ", ".join(sorted(bad)))
                pruned_log.extend("%s (extra selection)" % b for b in sorted(bad))
                extra_selection = ""
                extra_vars = None
                var_decl = var_decl.replace(extra_var_decl, "")
                extra_var_decl = ""
                continue
            n = remove_fields(spec, bad)
            pruned_log.extend(sorted(bad))
            log.info("[%s] pruned %d field(s) not in this tenant's schema: %s", label, n, ", ".join(sorted(bad)))
            if rounds > 15 or not spec:
                raise
            continue
        except WizAPIError as exc:
            msg = str(exc).lower()
            if isinstance(exc, WizPermissionError):
                raise
            if order_by is not None and ("orderby" in msg or "order" in msg):
                log.info("[%s] orderBy rejected; retrying without ordering", label)
                order_by = None
                var_decl = var_decl.replace(", $orderBy: %s" % order_type, "")
                continue
            if ("maximum" in msg or "limit" in msg or "too many" in msg) and size > 50:
                size = max(50, size // 2)
                log.info("[%s] page size rejected; reducing to %d", label, size)
                continue
            raise
        conn = data.get(root) or {}
        if use_edges:
            batch = [e.get("node") for e in (conn.get("edges") or []) if e and e.get("node")]
        else:
            batch = [n for n in (conn.get("nodes") or []) if n]
        nodes.extend(batch)
        if conn.get("totalCount") is not None:
            total = conn["totalCount"]
        page += 1
        meta["pages"] = page
        pi = conn.get("pageInfo") or {}
        log.info("[%s] page %d: +%d (running %d%s)", label, page, len(batch), len(nodes),
                 "/%s" % total if total is not None else "")
        if not pi.get("hasNextPage") or not pi.get("endCursor") or pi.get("endCursor") == after:
            break
        after = pi["endCursor"]
        if page >= max_pages:
            if max_pages == MAX_PAGES:
                log.warning("[%s] MAX_PAGES guard hit", label)
            break
    meta["page_size"] = size
    return nodes, total, meta


# --------------------------------------------------------------------------- #
# Graph query analysis (Control.query JSON -> inputs, levers)
# --------------------------------------------------------------------------- #

FINDING_TYPES = {
    "CONFIGURATION_FINDING": "Cloud Configuration Finding (CCR output)",
    "CONFIGURATION_RULE": "Cloud Configuration Rule reference",
    "HOST_CONFIGURATION_FINDING": "Host Configuration Finding",
    "HOST_CONFIGURATION_RULE": "Host Configuration Rule reference",
    "VULNERABILITY": "Vulnerability finding",
    "WEAKNESS": "Weakness (non-CVE) finding",
    "SECRET": "Secret finding",
    "SECRET_INSTANCE": "Secret instance",
    "DATA_FINDING": "Data (DSPM) finding",
    "MALWARE": "Malware finding",
    "MALWARE_INSTANCE": "Malware instance",
    "EXCESSIVE_ACCESS_FINDING": "Excessive access (CIEM) finding",
    "SECURITY_EVENT": "Security event / detection",
    "SECURITY_TOOL_FINDING": "Third-party security tool finding",
    "SECURITY_TOOL_SCAN": "Third-party security scan",
    "SOFTWARE_SUPPLY_CHAIN_FINDING": "Supply chain finding",
    "SAST_FINDING": "SAST finding",
    "SENSITIVE_DATA_FINDING": "Sensitive data finding",
}

EXPOSURE_TYPES = {"NETWORK_EXPOSURE": "Network exposure path (Wiz network analysis)", "ENDPOINT": "Network endpoint"}
CCR_TYPES = ("CONFIGURATION_FINDING", "CONFIGURATION_RULE")

FIX_RULE_SINGLE = "Rule level: config rule acting as a control"
FIX_RULE_CCR = "Rule level: graph control built on CCR findings"
FIX_FINDING_OTHER = "Finding level: other finding types (vulnerability, secret, data, malware)"
FIX_CONTROL = "Control level: exposure, permissions or properties only"
FIX_UNKNOWN = "Unknown: query not available"
FIX_ORDER = [FIX_RULE_SINGLE, FIX_RULE_CCR, FIX_FINDING_OTHER, FIX_CONTROL, FIX_UNKNOWN]

EXPOSURE_KEY_RE = re.compile(
    r"expos|internetfacing|publicexposure|publiclyaccessible|opentoallinternet|hasPublicIp|externallyfacing|"
    r"accessiblefrom|isinternet|publicip|hasexternalexposure|hasinternetexposure|inboundinternet", re.I)
PERMISSION_KEY_RE = re.compile(
    r"admin|privileg|permission|canassume|effective|entitle|highprivilege|iamrole|accesskey|passrole|wildcard", re.I)
SENSITIVE_KEY_RE = re.compile(r"sensitivedata|dataclassif|hassensitive|pii|phi|pci", re.I)
VULN_KEY_RE = re.compile(r"vulnerab|cve|exploit|cisa|epss|knownexploited|hasfix", re.I)
TAG_KEY_RE = re.compile(r"^tags?$|tag\.|\.tags|tagkey|tagvalue", re.I)
STATUS_KEYS = {"status", "state"}
EXPOSURE_RELATIONSHIPS = {"EXPOSES", "EXPOSED_TO", "PUBLICLY_EXPOSED", "APPLIES_TO", "ROUTES_TO", "ALLOWS_ACCESS"}
PERMISSION_RELATIONSHIPS = {"CAN_ASSUME", "ASSUMES", "ENTITLED_TO", "HAS_PERMISSION", "PERMITS", "CAN_ACCESS",
                            "CAN_ADMINISTER", "HAS_ADMIN_PRIVILEGES", "HAS_EFFECTIVE_PERMISSION", "ACTS_AS"}


class QueryAnalysis(object):
    def __init__(self):
        self.root_types = []
        self.all_types = OrderedDict()      # type -> {"negated": bool, "optional": bool, "where_keys": set, "depth": int}
        self.relationships = Counter()
        self.where_keys = set()
        self.negated = 0
        self.optional = 0
        self.rule_ids = set()             # UUIDs referenced where a rule/finding node is filtered by id
        self.rule_short_ids = set()
        self.literal_uuids = set()
        self.depth = 0
        self.parse_error = None

    # -- derived flags --------------------------------------------------- #
    @property
    def finding_inputs(self):
        return [t for t in self.all_types if t in FINDING_TYPES or t.endswith("_FINDING")]

    @property
    def uses_ccr(self):
        return any(t in CCR_TYPES for t in self.all_types)

    @property
    def other_finding_types(self):
        return [t for t in self.finding_inputs if t not in CCR_TYPES]

    @property
    def has_other_findings(self):
        """Non-CCR finding inputs: by entity type, or by a property that encodes one (e.g. a vulnerability flag)."""
        return bool(self.other_finding_types or self.uses_vuln or self.uses_sensitive_data
                    or self.uses_secrets or self.uses_malware)

    @property
    def uses_vuln(self):
        return any(t in ("VULNERABILITY", "WEAKNESS") for t in self.all_types) or any(VULN_KEY_RE.search(k) for k in self.where_keys)

    @property
    def uses_exposure(self):
        return (any(EXPOSURE_KEY_RE.search(k) for k in self.where_keys)
                or any(r in EXPOSURE_RELATIONSHIPS for r in self.relationships)
                or "NETWORK_EXPOSURE" in self.all_types or "ENDPOINT" in self.all_types)

    @property
    def uses_permissions(self):
        return (any(PERMISSION_KEY_RE.search(k) for k in self.where_keys)
                or any(r in PERMISSION_RELATIONSHIPS for r in self.relationships)
                or "EXCESSIVE_ACCESS_FINDING" in self.all_types)

    @property
    def uses_sensitive_data(self):
        return "DATA_FINDING" in self.all_types or "SENSITIVE_DATA_FINDING" in self.all_types or any(SENSITIVE_KEY_RE.search(k) for k in self.where_keys)

    @property
    def uses_secrets(self):
        return any(t in ("SECRET", "SECRET_INSTANCE") for t in self.all_types)

    @property
    def uses_malware(self):
        return any(t in ("MALWARE", "MALWARE_INSTANCE") for t in self.all_types)

    @property
    def uses_tags(self):
        return any(TAG_KEY_RE.search(k) for k in self.where_keys)

    def input_classes(self):
        out = []
        if self.uses_ccr:
            out.append("CCR finding")
        if self.uses_exposure:
            out.append("Network exposure")
        if self.uses_permissions:
            out.append("Permissions / CIEM")
        if self.uses_vuln:
            out.append("Vulnerability")
        if self.uses_sensitive_data:
            out.append("Sensitive data")
        if self.uses_secrets:
            out.append("Secrets")
        if self.uses_malware:
            out.append("Malware")
        if any(t in ("SECURITY_EVENT",) for t in self.all_types):
            out.append("Threat / detection")
        if any(t in ("SECURITY_TOOL_FINDING", "SECURITY_TOOL_SCAN") for t in self.all_types):
            out.append("Third-party finding")
        if self.uses_tags:
            out.append("Tags")
        if not out:
            out.append("Graph-native (relationships / properties only)")
        return out

    def tuning_lever(self):
        """Where a false positive would actually be fixed. The crux of the controls-vs-inputs debate."""
        levers = []
        if self.uses_ccr:
            levers.append("CCR input: fix or scope the Cloud Configuration Rule (Ignore Rule on the finding, clone/patch the CCR); the control inherits the correction")
        if self.uses_exposure:
            levers.append("Exposure is computed by Wiz network analysis, not by a rule: validate the path (SG/NACL/LB/WAF); scope with Ignore Rule or refine the control")
        if self.uses_permissions:
            levers.append("Effective permissions come from CIEM (ignores ExternalId/SourceIp-style conditions): check the condition-key caveat; refine the control or exception")
        if self.uses_vuln:
            levers.append("Vulnerability data: fix per vuln policy; control-level thresholds (severity/exploitability) can be refined in a clone")
        if self.uses_sensitive_data:
            levers.append("Sensitive data comes from DSPM classifiers: validate the classifier match; scope at control level")
        if self.uses_tags:
            levers.append("Tag-driven condition: confirm tagging standard is applied consistently")
        if not levers:
            levers.append("Graph-native logic: only control-level levers apply (clone + refine query, Project/BI scope, Ignore Rule/exception, disable)")
        return " | ".join(levers)


def _collect_where_keys(where, analysis, type_name, prefix=""):
    if not isinstance(where, dict):
        return
    for k, v in where.items():
        if k in ("AND", "OR", "NOT") and isinstance(v, list):
            for sub in v:
                _collect_where_keys(sub, analysis, type_name, prefix)
            continue
        key = (prefix + k) if prefix else k
        if k.upper() in ("EQUALS", "CONTAINS", "IN", "GREATER_THAN", "LESS_THAN", "STARTS_WITH", "ENDS_WITH",
                         "GREATER_THAN_OR_EQUAL", "LESS_THAN_OR_EQUAL", "IS_SET", "NOT_EQUALS", "CONTAINS_ANY",
                         "CONTAINS_ALL", "ENDS_WITH_ANY", "STARTS_WITH_ANY"):
            vals = v if isinstance(v, list) else [v]
            for val in vals:
                if isinstance(val, str):
                    if UUID_RE.match(val):
                        analysis.literal_uuids.add(val)
                        if type_name in ("CONFIGURATION_FINDING", "CONFIGURATION_RULE", "HOST_CONFIGURATION_RULE") or "rule" in prefix.lower():
                            analysis.rule_ids.add(val)
                    elif type_name in ("CONFIGURATION_RULE", "CONFIGURATION_FINDING") and re.match(r"^[A-Za-z][A-Za-z0-9]*-\d{2,4}$", val):
                        analysis.rule_short_ids.add(val)
            continue
        analysis.where_keys.add(key)
        if type_name in analysis.all_types:
            analysis.all_types[type_name]["where_keys"].add(key)
        if isinstance(v, dict):
            _collect_where_keys(v, analysis, type_name, key + ".")


def _walk(node, analysis, depth=0, negated=False, optional=False):
    if not isinstance(node, dict):
        return
    analysis.depth = max(analysis.depth, depth)
    types = node.get("type") or []
    if isinstance(types, str):
        types = [types]
    for t in types:
        if not isinstance(t, str):
            continue
        if depth == 0:
            analysis.root_types.append(t)
        entry = analysis.all_types.setdefault(t, {"negated": False, "optional": False, "where_keys": set(), "depth": depth})
        entry["negated"] = entry["negated"] or negated
        entry["optional"] = entry["optional"] or optional
        entry["depth"] = min(entry["depth"], depth)
    for t in types or ["?"]:
        _collect_where_keys(node.get("where"), analysis, t if isinstance(t, str) else "?")
    for rel in node.get("relationships") or []:
        if not isinstance(rel, dict):
            continue
        rtypes = rel.get("type") or []
        if isinstance(rtypes, dict):
            rtypes = [rtypes]
        for rt in rtypes:
            name = rt.get("type") if isinstance(rt, dict) else rt
            if isinstance(name, str):
                analysis.relationships[name] += 1
        neg = bool(rel.get("negate"))
        opt = bool(rel.get("optional"))
        analysis.negated += 1 if neg else 0
        analysis.optional += 1 if opt else 0
        _walk(rel.get("with"), analysis, depth + 1, negated or neg, optional or opt)


def analyse_query(raw):
    a = QueryAnalysis()
    if raw in (None, "", {}):
        a.parse_error = "no query returned"
        return a
    q = raw
    if isinstance(raw, str):
        try:
            q = json.loads(raw)
        except ValueError as exc:
            a.parse_error = "query is not JSON: %s" % exc
            return a
    try:
        if isinstance(q, list):
            for item in q:
                _walk(item, a)
        else:
            _walk(q, a)
    except Exception as exc:  # noqa: BLE001 - never let a weird query kill the export
        a.parse_error = "walk failed: %s" % exc
    return a


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
            frac = re.match(r"(\d+)(.*)", tail)
            v = head + "." + frac.group(1)[:6] + frac.group(2)
        dt = datetime.fromisoformat(v)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return None


def iso_z(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def days_between(later, earlier):
    if not later or not earlier:
        return None
    return round((later - earlier).total_seconds() / 86400.0, 1)


def clean(value, limit=MAX_CELL_CHARS):
    if value is None:
        return ""
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (int, float)):
        return value
    if isinstance(value, (dict, list)):
        value = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    s = ILLEGAL_XLSX_RE.sub("", str(value))
    if len(s) > limit:
        s = s[: limit - 15] + " ...[truncated]"
    return s


def join_names(items, key="name", cap=10):
    if not items:
        return ""
    names = []
    for it in items:
        if isinstance(it, dict):
            n = it.get(key) or it.get("id")
        else:
            n = it
        if n:
            names.append(str(n))
    extra = "" if len(names) <= cap else " (+%d more)" % (len(names) - cap)
    return ", ".join(names[:cap]) + extra


def frameworks_of(node):
    subs = node.get("securitySubCategories") or []
    fw, cats = OrderedDict(), OrderedDict()
    for s in subs:
        if not isinstance(s, dict):
            continue
        cat = s.get("category") or {}
        f = (cat.get("framework") or {}).get("name")
        if f:
            fw[f] = True
        c = cat.get("name")
        if c:
            cats["%s / %s" % (f, c) if f else c] = True
    return ", ".join(fw.keys()), ", ".join(list(cats.keys())[:12])


def origin_of(node):
    if node.get("_synthetic"):
        return "Unknown (control not returned)"
    cb = node.get("createdBy")
    if cb is None:
        return "Built-in"
    if isinstance(cb, str):
        return "Built-in" if cb.upper() in ("BUILT_IN", "BUILTIN", "WIZ") else "Custom"
    if isinstance(cb, dict):
        return "Custom" if (cb.get("id") or cb.get("name") or cb.get("email")) else "Built-in"
    return "Custom"


def bi_scope(node):
    parts = []
    mapping = [("enabledForHBI", "HBI"), ("enabledForMBI", "MBI"), ("enabledForLBI", "LBI"), ("enabledForUnattributed", "Unattributed")]
    seen_any = False
    for field, label in mapping:
        if field in node:
            seen_any = True
            if node.get(field):
                parts.append(label)
    if not seen_any:
        return "n/a (fields not in schema)"
    return ", ".join(parts) if parts else "None (all BI levels off)"


def is_config_control(ctrl):
    """A Cloud Configuration Rule functioning as a control (one rule, no correlation)."""
    return bool(ctrl.get("type") == "CLOUD_CONFIGURATION" or ctrl.get("sourceCloudConfigurationRule"))


def fix_location(ctrl, analysis):
    """Exclusive bucket: where a false positive from this control would be corrected."""
    if is_config_control(ctrl):
        return FIX_RULE_SINGLE
    if analysis.parse_error and not analysis.all_types:
        return FIX_UNKNOWN
    if analysis.uses_ccr:
        return FIX_RULE_CCR
    if analysis.has_other_findings:
        return FIX_FINDING_OTHER
    return FIX_CONTROL


def pct(part, whole):
    return round(100.0 * part / whole, 1) if whole else None


def issue_link(app_url, issue_id):
    return "%s/issues#~(issue~'%s)" % (app_url.rstrip("/"), issue_id)


def entity_link(app_url, ent_id, ent_type):
    if not ent_id or not ent_type:
        return ""
    return "%s/issues#~(entity~(~'%s*2c%s))" % (app_url.rstrip("/"), ent_id, ent_type)


# --------------------------------------------------------------------------- #
# Pull orchestration
# --------------------------------------------------------------------------- #

def pull_controls(client, explorer, args, evidence):
    pruned = []
    spec = OrderedDict(CONTROL_SPEC)
    if explorer.available:
        node_t = explorer.node_type_of("controls") or "Control"
        spec = explorer.prune_spec(node_t, CONTROL_SPEC, pruned)
    extra_sel, extra_vars, extra_decl = "", None, ""
    if explorer.available:
        node_t = explorer.node_type_of("controls") or "Control"
        if "issueAnalytics" in explorer.type_fields(node_t):
            sel_type = "ControlIssueAnalyticsSelection"
            in_fields = explorer.input_fields(sel_type)
            evidence["issueAnalytics_input_fields"] = ", ".join(sorted(in_fields.keys())) or "(none returned)"
            selection = {}
            if in_fields:
                # Prefer an "open issues" selection when the input type exposes a status filter.
                for fname in ("status", "statuses", "issueStatus"):
                    if fname in in_fields:
                        selection[fname] = ["OPEN", "IN_PROGRESS"]
                        break
            extra_sel = "issueAnalytics(selection: $sel) { issueCount }"
            extra_vars = {"sel": selection}
            extra_decl = ", $sel: %s" % sel_type
            evidence["issueAnalytics_selection"] = json.dumps(selection)
    nodes, total, meta = paged_fetch(client, "controls", spec, args.page_size, "controls", pruned,
                                     filter_by={}, filter_type="ControlFilters",
                                     extra_selection=extra_sel, extra_vars=extra_vars, extra_var_decl=extra_decl)
    evidence["controls"] = {"totalCount": total, "fetched": len(nodes), "pages": meta["pages"],
                            "selection": meta["selection"], "pruned": pruned}
    return nodes


def pull_issues(client, explorer, args, as_of, evidence):
    """Per Issue type: open/in-progress Issues (--statuses) plus RESOLVED/REJECTED Issues whose status changed
    in the last --history-days. Each (type, scope) is a separate pull so every totalCount is reproducible."""
    pruned = []
    spec = json.loads(json.dumps(ISSUE_SPEC), object_pairs_hook=OrderedDict)  # deep copy; pruning mutates it
    order = {"field": "CREATED_AT", "direction": "ASC"}
    issues, seen = [], set()
    totals = OrderedDict()
    failed = []
    for itype in args.issue_types:
        base_filter = {"type": [itype]}
        if args.severity:
            base_filter["severity"] = args.severity
        if args.project:
            base_filter["project"] = args.project
        scopes = []
        if args.statuses:
            f = dict(base_filter)
            f["status"] = args.statuses
            scopes.append(("current", f))
        if args.history_days and args.history_days > 0:
            cutoff = as_of - timedelta(days=args.history_days)
            f = dict(base_filter)
            f["status"] = ["RESOLVED", "REJECTED"]
            f["statusChangedAt"] = {"after": iso_z(cutoff)}
            scopes.append(("history", f))
        for label, flt in scopes:
            key = "%s %s" % (label, itype)
            try:
                nodes, total, meta = paged_fetch(client, "issuesV2", spec, args.page_size, "issues:%s" % key, pruned,
                                                 filter_by=flt, filter_type="IssueFilters",
                                                 order_by=order, order_type="IssueOrder")
            except WizPermissionError:
                raise
            except WizAPIError as exc:
                if itype == "TOXIC_COMBINATION" or len(args.issue_types) == 1:
                    raise
                log.warning("[issues:%s] pull failed, continuing without this Issue type: %s", key, str(exc)[:200])
                totals[key] = {"filter": flt, "totalCount": None, "fetched": 0, "pages": 0, "error": str(exc)[:200]}
                failed.append(key)
                break
            totals[key] = {"filter": flt, "totalCount": total, "fetched": len(nodes), "pages": meta["pages"]}
            for n in nodes:
                if n.get("id") in seen:
                    continue
                seen.add(n.get("id"))
                n["_scope"] = label
                issues.append(n)
    evidence["issues"] = {"scopes": totals, "unique": len(issues), "pruned": pruned, "failed": failed}
    return issues


def pull_ccrs(client, explorer, args, evidence, wanted_ids):
    """Resolve CCR UUIDs referenced by control queries to short IDs. Pulls the whole root (cheap: ~8 pages)."""
    if not wanted_ids or args.no_ccr_resolve:
        return {}
    if explorer.available and not explorer.has_root("cloudConfigurationRules"):
        evidence["ccr"] = {"status": "root not in schema"}
        return {}
    pruned = []
    spec = OrderedDict(CCR_SPEC)
    if explorer.available:
        node_t = explorer.node_type_of("cloudConfigurationRules") or "CloudConfigurationRule"
        spec = explorer.prune_spec(node_t, CCR_SPEC, pruned)
    try:
        nodes, total, meta = paged_fetch(client, "cloudConfigurationRules", spec, args.page_size, "ccr", pruned,
                                         filter_by={}, filter_type="CloudConfigurationRuleFilters")
    except WizPermissionError as exc:
        evidence["ccr"] = {"status": "FORBIDDEN (needs read:cloud_configuration_rule): %s" % str(exc)[:200]}
        return None
    evidence["ccr"] = {"status": "ok", "totalCount": total, "fetched": len(nodes), "pages": meta["pages"], "pruned": pruned}
    return {n["id"]: n for n in nodes if n.get("id")}


# --------------------------------------------------------------------------- #
# Aggregation
# --------------------------------------------------------------------------- #

OPEN_STATUSES = ("OPEN", "IN_PROGRESS")


def control_id_of_issue(issue, ccr_to_control=None):
    """Issue -> (control id, control name) from sourceRules (Control, or a config rule functioning as a control)."""
    for r in issue.get("sourceRules") or []:
        if not isinstance(r, dict):
            continue
        tn = r.get("__typename")
        if tn == "Control" and r.get("id"):
            return r["id"], r.get("name")
        if tn == "CloudConfigurationRule":
            c = r.get("control") or {}
            if c.get("id"):
                return c["id"], c.get("name") or r.get("name")
            if r.get("id") and ccr_to_control and r["id"] in ccr_to_control:
                return ccr_to_control[r["id"]]
            if r.get("id"):
                return "ccr:" + r["id"], r.get("name")
        if tn == "CloudEventRule" and r.get("id"):
            return "cer:" + r["id"], r.get("name")
    c = issue.get("control") or {}
    if c.get("id"):
        return c["id"], c.get("name")
    return None, None


def most_specific_project(projects, project_issue_counts):
    """Issues belong to every Project containing the resource; pick the one with the fewest issues tenant-wide."""
    cands = [p for p in (projects or []) if isinstance(p, dict) and p.get("id")]
    if not cands:
        return None
    return min(cands, key=lambda p: (project_issue_counts.get(p["id"], 0), p.get("name") or ""))


def aggregate(controls, issues, as_of, args):
    per = defaultdict(lambda: {
        "open": 0, "in_progress": 0, "sev": Counter(), "ages": [], "entities": set(), "projects": Counter(),
        "clouds": Counter(), "subs": set(), "ticketed": 0, "past_due": 0, "due_set": 0,
        "resolved": 0, "rejected": 0, "reasons": Counter(), "rejected_reasons": Counter(),
        "fp_rejected": 0, "object_deleted": 0, "resolved_ages": [], "entity_types": Counter(),
        "history_min": None, "history_max": None, "created_90d": 0, "name": None, "issues": [],
    })
    project_issue_counts = Counter()
    for iss in issues:
        for p in iss.get("projects") or []:
            if isinstance(p, dict) and p.get("id"):
                project_issue_counts[p["id"]] += 1
    cutoff_90 = as_of - timedelta(days=90)
    ccr_to_control = {}
    for c in controls:
        src = c.get("sourceCloudConfigurationRule")
        if isinstance(src, dict) and src.get("id"):
            ccr_to_control[src["id"]] = (c["id"], c.get("name"))
    for iss in issues:
        cid, cname = control_id_of_issue(iss, ccr_to_control)
        if not cid:
            cid, cname = "unknown", "(no source rule returned)"
        iss["_control_id"] = cid
        iss["_control_name"] = cname
        agg = per[cid]
        agg["name"] = agg["name"] or cname
        agg["issues"].append(iss)
        status = iss.get("status")
        created = parse_dt(iss.get("createdAt"))
        iss["_created_dt"] = created
        iss["_age_days"] = days_between(as_of, created)
        ent = iss.get("entitySnapshot") or {}
        due = parse_dt(iss.get("dueAt"))
        prj = most_specific_project(iss.get("projects"), project_issue_counts)
        iss["_primary_project"] = (prj or {}).get("name") or ""
        if created and created >= cutoff_90:
            agg["created_90d"] += 1
        if status in OPEN_STATUSES:
            agg["open" if status == "OPEN" else "in_progress"] += 1
            agg["sev"][iss.get("severity") or "?"] += 1
            if iss["_age_days"] is not None:
                agg["ages"].append(iss["_age_days"])
            if ent.get("id"):
                agg["entities"].add(ent["id"])
            agg["entity_types"][ent.get("type") or "?"] += 1
            if prj:
                agg["projects"][prj.get("name") or prj.get("id")] += 1
            if ent.get("cloudPlatform"):
                agg["clouds"][ent["cloudPlatform"]] += 1
            if ent.get("subscriptionExternalId"):
                agg["subs"].add(ent["subscriptionExternalId"])
            if iss.get("serviceTickets"):
                agg["ticketed"] += 1
            if due:
                agg["due_set"] += 1
                if due < as_of:
                    agg["past_due"] += 1
                    iss["_past_due"] = True
        elif status == "RESOLVED":
            agg["resolved"] += 1
            reason = iss.get("resolutionReason") or "UNSPECIFIED"
            agg["reasons"][reason] += 1
            if reason == "OBJECT_DELETED":
                agg["object_deleted"] += 1
            res = parse_dt(iss.get("resolvedAt")) or parse_dt(iss.get("statusChangedAt"))
            d = days_between(res, created)
            if d is not None:
                agg["resolved_ages"].append(d)
        elif status == "REJECTED":
            agg["rejected"] += 1
            reason = iss.get("resolutionReason") or "UNSPECIFIED"
            agg["rejected_reasons"][reason] += 1
            if reason == "FALSE_POSITIVE":
                agg["fp_rejected"] += 1
    return per


def control_row(ctrl, agg, analysis, ccr_map, args, as_of):
    fw, cats = frameworks_of(ctrl)
    open_total = (agg["open"] + agg["in_progress"]) if agg else 0
    closed = (agg["resolved"] + agg["rejected"]) if agg else 0
    ages = agg["ages"] if agg else []
    reason_mix = ", ".join("%s %d" % (k, v) for k, v in agg["reasons"].most_common(6)) if agg else ""
    rej_mix = ", ".join("%s %d" % (k, v) for k, v in agg["rejected_reasons"].most_common(6)) if agg else ""
    top_projects = ", ".join("%s (%d)" % (k, v) for k, v in agg["projects"].most_common(5)) if agg else ""
    clouds = ", ".join("%s %d" % (k, v) for k, v in agg["clouds"].most_common()) if agg else ""
    ent_types = ", ".join("%s %d" % (k, v) for k, v in agg["entity_types"].most_common(5)) if agg else ""
    ccr_refs = []
    for rid in sorted(analysis.rule_ids):
        c = (ccr_map or {}).get(rid)
        if c:
            ccr_refs.append("%s %s%s" % (c.get("shortId") or rid[:8], (c.get("name") or "")[:60],
                                         "" if c.get("enabled", True) else " [DISABLED]"))
        else:
            ccr_refs.append(rid)
    ccr_refs.extend(sorted(analysis.rule_short_ids))
    ia = ctrl.get("issueAnalytics") or {}
    is_cfg = is_config_control(ctrl)
    src = ctrl.get("sourceCloudConfigurationRule") if isinstance(ctrl.get("sourceCloudConfigurationRule"), dict) else {}
    if is_cfg and not ccr_refs and src:
        ccr_refs = [("%s %s" % (src.get("shortId") or "", src.get("name") or "")).strip()]
    if is_cfg:
        control_class = "Config rule as control"
        lever = ("One Cloud Configuration Rule functioning as a control, no correlation: tune or scope the rule itself "
                 "(Ignore Rule on its findings, clone/patch the CCR), or turn off Function as Control to stop the Issues "
                 "and keep the findings")
    else:
        control_class = "Unknown (control not returned)" if ctrl.get("_synthetic") else "Graph control"
        lever = analysis.tuning_lever() if not (analysis.parse_error and not analysis.all_types) else "Query not available: review in the console"
    row = OrderedDict([
        ("Control ID", ctrl.get("id")),
        ("Control Name", ctrl.get("name")),
        ("Origin", origin_of(ctrl)),
        ("Control Type", ctrl.get("type")),
        ("Control Class", control_class),
        ("Enabled", ctrl.get("enabled")),
        ("Severity", ctrl.get("severity")),
        ("Business Impact Scope", bi_scope(ctrl)),
        ("Project Scope", (ctrl.get("scopeProject") or {}).get("name") if isinstance(ctrl.get("scopeProject"), dict) else ctrl.get("scopeProject")),
        ("Frameworks", fw),
        ("Categories", cats),
        ("Risks", ", ".join(ctrl.get("risks") or []) if isinstance(ctrl.get("risks"), list) else ctrl.get("risks")),
        ("Tags", ctrl.get("tags")),
        ("Description", ctrl.get("description")),
        ("Resolution Recommendation", ctrl.get("resolutionRecommendation")),
        ("Source CCR (config-as-control)", (ctrl.get("sourceCloudConfigurationRule") or {}).get("shortId") or (ctrl.get("sourceCloudConfigurationRule") or {}).get("name")),
        ("Created By", (ctrl.get("createdBy") or {}).get("name") or (ctrl.get("createdBy") or {}).get("email") if isinstance(ctrl.get("createdBy"), dict) else ctrl.get("createdBy")),
        ("Created At", ctrl.get("createdAt")),
        ("Updated At", ctrl.get("updatedAt")),
        ("Last Run", ctrl.get("lastRunAt")),
        ("Last Run Error", ctrl.get("lastRunError")),
        ("Supports NRT", ctrl.get("supportsNRT")),
        ("Has Auto-Remediation", ctrl.get("hasAutoRemediation")),
        # -- graph query analysis
        ("Root Entity Type(s)", ", ".join(analysis.root_types)),
        ("All Entity Types in Query", ", ".join(analysis.all_types.keys())),
        ("Finding-Type Inputs", ", ".join(analysis.finding_inputs)),
        ("Input Classes", "CCR finding (single rule)" if is_cfg else ", ".join(analysis.input_classes())),
        ("Built on CCR Findings?", "Yes (single config rule)" if is_cfg else ("Yes" if analysis.uses_ccr else "No")),
        ("Referenced CCRs", "; ".join(ccr_refs)),
        ("Exposure Condition?", "Yes" if analysis.uses_exposure else "No"),
        ("Permission/CIEM Condition?", "Yes" if analysis.uses_permissions else "No"),
        ("Vulnerability Condition?", "Yes" if analysis.uses_vuln else "No"),
        ("Sensitive Data Condition?", "Yes" if analysis.uses_sensitive_data else "No"),
        ("Tag Condition?", "Yes" if analysis.uses_tags else "No"),
        ("Negated Relationships", analysis.negated),
        ("Optional Relationships", analysis.optional),
        ("Relationship Types", ", ".join("%s" % k for k, _ in analysis.relationships.most_common(10))),
        ("Where Keys", ", ".join(sorted(analysis.where_keys)[:25])),
        ("Query Depth", analysis.depth),
        ("Query Parse Note", "" if (is_cfg and not analysis.all_types) else (analysis.parse_error or "")),
        ("Fix Location", fix_location(ctrl, analysis)),
        ("Where a False Positive Gets Fixed", lever),
        # -- issue statistics
        ("Open Issues", agg["open"] if agg else 0),
        ("In Progress Issues", agg["in_progress"] if agg else 0),
        ("Open + In Progress", open_total),
        ("Open Critical", agg["sev"].get("CRITICAL", 0) if agg else 0),
        ("Open High", agg["sev"].get("HIGH", 0) if agg else 0),
        ("Open Medium", agg["sev"].get("MEDIUM", 0) if agg else 0),
        ("Open Low/Info", (agg["sev"].get("LOW", 0) + agg["sev"].get("INFORMATIONAL", 0)) if agg else 0),
        ("Unique Open Entities", len(agg["entities"]) if agg else 0),
        ("Open Entity Types", ent_types),
        ("Oldest Open (days)", max(ages) if ages else None),
        ("Median Open Age (days)", round(statistics.median(ages), 1) if ages else None),
        ("Open Past Due", agg["past_due"] if agg else 0),
        ("Open With Ticket %", pct(agg["ticketed"], open_total) if agg else None),
        ("Top Projects (open)", top_projects),
        ("Cloud Platforms (open)", clouds),
        ("Subscriptions (open)", len(agg["subs"]) if agg else 0),
        ("Created Last 90d", agg["created_90d"] if agg else 0),
        ("Resolved (window)", agg["resolved"] if agg else 0),
        ("Rejected (window)", agg["rejected"] if agg else 0),
        ("Resolution Reason Mix", reason_mix),
        ("Rejection Reason Mix", rej_mix),
        ("Rejected as FALSE_POSITIVE", agg["fp_rejected"] if agg else 0),
        ("Reject Rate % (rejected / closed)", pct(agg["rejected"], closed) if agg else None),
        ("OBJECT_DELETED % of Resolved", pct(agg["object_deleted"], agg["resolved"]) if agg else None),
        ("Median Days-to-Resolve", round(statistics.median(agg["resolved_ages"]), 1) if agg and agg["resolved_ages"] else None),
        ("API issueAnalytics.issueCount", ia.get("issueCount") if isinstance(ia, dict) else None),
        ("Issues Rows in Workbook", 0),  # filled later
    ])
    return row


TRIAGE_CONTROL_COLUMNS = OrderedDict([
    ("Applicable at [ORG]?", "applicable"),
    ("Premise Holds Here?", "premise"),
    ("Compensating Controls", None),
    ("Inputs Accurate?", "inputs"),
    ("Sample Reviewed (n)", None),
    ("True Positives (n)", None),
    ("False Positives (n)", None),
    ("Needs Info (n)", None),
    ("Primary FP Cause", "fp_cause"),
    ("Severity Appropriate?", "severity_ok"),
    ("Disposition", "disposition"),
    ("Governance Outcome", "outcome"),
    ("Owner Team", None),
    ("Jira Ticket", None),
    ("Change Record (CR #)", None),
    ("Reviewer", None),
    ("Review Date", None),
    ("Notes / Evidence", None),
])

TRIAGE_ISSUE_COLUMNS = OrderedDict([
    ("Verdict", "verdict"),
    ("FP Cause", "fp_cause"),
    ("Which Input Is Wrong", None),
    ("Recommended Action", "action"),
    ("Reviewer", None),
    ("Review Date", None),
    ("Notes / Evidence", None),
])

LISTS = OrderedDict([
    ("applicable", ["Yes", "No - technology or pattern not used here", "No - risk accepted by architecture",
                    "Partially - needs Project/BI scoping", "Undetermined"]),
    ("premise", ["Yes", "Partially", "No"]),
    ("inputs", ["Yes", "CCR finding inaccurate", "Exposure analysis inaccurate", "Permission (CIEM) over-report",
                "Vulnerability data stale", "Scan coverage gap", "Mixed", "Not reviewed"]),
    ("fp_cause", ["None - true positives", "Input finding wrong (CCR)", "Exposure calculation wrong",
                  "CIEM over-report (condition keys ignored)", "Sanctioned pattern not modelled",
                  "Stale or deleted entity", "Scan coverage gap", "Control logic too broad",
                  "Duplicate of another control", "Other (see notes)"]),
    ("severity_ok", ["Yes", "Too high", "Too low"]),
    ("disposition", ["Keep as-is", "Keep - scope by Project or Business Impact", "Keep - Ignore Rule for sanctioned pattern",
                     "Tune input rule (CCR)", "Clone and refine query (custom control)", "Disable Issue generation only",
                     "Disable control", "Escalate to Wiz support", "Severity override (last resort)", "Undetermined"]),
    ("outcome", ["A - Fix the resource (no Wiz change)", "B - Scoped ignore / exception", "C - Deactivate (scoped or tenant-wide)",
                 "D - Patched custom control", "E - Vendor escalation", "F - Severity override", "Rule validated - no change"]),
    ("verdict", ["True positive", "False positive", "Accepted risk / sanctioned", "Needs info", "Duplicate"]),
    ("action", ["Fix resource", "Ignore Rule / exception", "Tune CCR", "Refine control", "Disable control",
                "Escalate to Wiz", "None"]),
])


def issue_row(iss, app_url):
    ent = iss.get("entitySnapshot") or {}
    tickets = iss.get("serviceTickets") or []
    bi = [((p.get("riskProfile") or {}).get("businessImpact") or "") for p in (iss.get("projects") or []) if isinstance(p, dict)]
    return OrderedDict([
        ("Issue ID", iss.get("id")),
        ("Control ID", iss.get("_control_id")),
        ("Control Name", iss.get("_control_name")),
        ("Scope", "Current" if iss.get("_scope") == "current" else "History"),
        ("Issue Type", iss.get("type")),
        ("Severity", iss.get("severity")),
        ("Status", iss.get("status")),
        ("Created At", iss.get("createdAt")),
        ("Age (days)", iss.get("_age_days")),
        ("Due At", iss.get("dueAt")),
        ("Past Due", "Yes" if iss.get("_past_due") else ""),
        ("Status Changed At", iss.get("statusChangedAt")),
        ("Resolved At", iss.get("resolvedAt")),
        ("Resolution Reason", iss.get("resolutionReason")),
        ("Entity Name", ent.get("name")),
        ("Entity Type", ent.get("type")),
        ("Native Type", ent.get("nativeType")),
        ("Entity Status", ent.get("status")),
        ("Cloud", ent.get("cloudPlatform")),
        ("Region", ent.get("region")),
        ("Subscription", ent.get("subscriptionName")),
        ("Subscription ID", ent.get("subscriptionExternalId")),
        ("Provider ID", ent.get("providerId") or ent.get("externalId")),
        ("Entity Tags", ent.get("tags")),
        ("Primary Project", iss.get("_primary_project")),
        ("All Projects", join_names(iss.get("projects"))),
        ("Business Impact", ", ".join(sorted({b for b in bi if b}))),
        ("Tickets", ", ".join("%s" % (t.get("externalId") or t.get("name")) for t in tickets if isinstance(t, dict))),
        ("Ticket URL", next((t.get("url") for t in tickets if isinstance(t, dict) and t.get("url")), "")),
        ("Issue Link", issue_link(app_url, iss.get("id")) if iss.get("id") else ""),
        ("Entity Link", entity_link(app_url, ent.get("id"), ent.get("type"))),
        ("Cloud Console URL", ent.get("cloudProviderURL")),
    ])


def select_issue_rows(per, args):
    """All issues, or a per-control sample that spreads across severity/status/project."""
    out = []
    for cid, agg in per.items():
        items = agg["issues"]
        if not args.sample_per_control or len(items) <= args.sample_per_control:
            chosen = items
        else:
            # Prefer current (open) issues, spread across projects, then fill from history.
            current = [i for i in items if i.get("_scope") == "current"]
            history = [i for i in items if i.get("_scope") != "current"]
            chosen, seen_proj = [], Counter()
            sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
            current.sort(key=lambda i: (sev_rank.get(i.get("severity"), 9), -(i.get("_age_days") or 0)))
            # round-robin over projects so one noisy project does not fill the sample
            buckets = defaultdict(list)
            for i in current:
                buckets[i.get("_primary_project") or ""].append(i)
            while len(chosen) < args.sample_per_control and any(buckets.values()):
                for k in list(buckets.keys()):
                    if buckets[k] and len(chosen) < args.sample_per_control:
                        chosen.append(buckets[k].pop(0))
            hist_quota = max(0, args.sample_per_control - len(chosen))
            hist_quota = max(hist_quota, min(len(history), max(2, args.sample_per_control // 5)))
            rejected = [i for i in history if i.get("status") == "REJECTED"]
            resolved = [i for i in history if i.get("status") == "RESOLVED"]
            chosen.extend(rejected[:hist_quota])
            chosen.extend(resolved[:max(0, hist_quota - len(rejected[:hist_quota]))])
        agg["sampled"] = len(chosen)
        out.extend(chosen)
    return out


# --------------------------------------------------------------------------- #
# Analysis: where does the fix belong, measured by Issue volume
# --------------------------------------------------------------------------- #

ANALYSIS_HEADERS = ["Group", "Controls", "Enabled", "Controls With Open Issues", "Open + In Progress Issues",
                    "% of Open Issues", "Open Critical + High", "Resolved (window)", "Rejected (window)",
                    "Reject Rate %", "Rejected as FALSE_POSITIVE"]


def build_analysis(selected, per, analyses):
    recs = []
    for c in selected:
        a = analyses[c["id"]]
        agg = per.get(c["id"])
        recs.append({
            "id": c["id"], "name": c.get("name") or c["id"], "cfg": is_config_control(c),
            "synthetic": bool(c.get("_synthetic")), "enabled": bool(c.get("enabled")),
            "severity": c.get("severity") or "", "fix": fix_location(c, a), "a": a,
            "open": (agg["open"] + agg["in_progress"]) if agg else 0,
            "crit_high": (agg["sev"].get("CRITICAL", 0) + agg["sev"].get("HIGH", 0)) if agg else 0,
            "resolved": agg["resolved"] if agg else 0,
            "rejected": agg["rejected"] if agg else 0,
            "fp": agg["fp_rejected"] if agg else 0,
        })
    total_open = sum(r["open"] for r in recs)

    def stat(label, subset):
        o = sum(r["open"] for r in subset)
        res = sum(r["resolved"] for r in subset)
        rej = sum(r["rejected"] for r in subset)
        return [label, len(subset), sum(1 for r in subset if r["enabled"]), sum(1 for r in subset if r["open"] > 0),
                o, pct(o, total_open), sum(r["crit_high"] for r in subset), res, rej, pct(rej, res + rej),
                sum(r["fp"] for r in subset)]

    by_fix = OrderedDict((name, [r for r in recs if r["fix"] == name]) for name in FIX_ORDER)
    buckets = [stat(name, subset) for name, subset in by_fix.items() if subset or name != FIX_UNKNOWN]
    buckets.append(stat("All controls in workbook", recs))
    rule_level = by_fix[FIX_RULE_SINGLE] + by_fix[FIX_RULE_CCR]
    any_finding = rule_level + by_fix[FIX_FINDING_OTHER]
    def mixed(r):
        return (not r["cfg"]) and (r["a"].uses_exposure or r["a"].uses_permissions)
    finding_only = [r for r in any_finding if not mixed(r)]
    finding_mixed = [r for r in any_finding if mixed(r)]
    rollups = [
        stat("Rule level combined (config-rule controls + graph controls built on CCR findings)", rule_level),
        stat("Any finding input (rule level + other finding types)", any_finding),
        stat("  of which: finding or rule is the only input (the fix is at the finding or rule)", finding_only),
        stat("  of which: finding combined with an exposure or permission condition (either side can be wrong)", finding_mixed),
        stat("Control level only (no finding input)", by_fix[FIX_CONTROL]),
    ]
    graph = [r for r in recs if not r["cfg"] and not r["synthetic"]]
    class_defs = [
        ("Graph controls built on CCR findings", lambda r: r["a"].uses_ccr),
        ("Graph controls with a vulnerability condition", lambda r: r["a"].uses_vuln),
        ("Graph controls with a secrets condition", lambda r: r["a"].uses_secrets),
        ("Graph controls with a sensitive-data condition", lambda r: r["a"].uses_sensitive_data),
        ("Graph controls with a malware condition", lambda r: r["a"].uses_malware),
        ("Graph controls with any finding-type input", lambda r: r["a"].uses_ccr or r["a"].has_other_findings),
        ("Graph controls with an exposure condition", lambda r: r["a"].uses_exposure),
        ("Graph controls with a permission / CIEM condition", lambda r: r["a"].uses_permissions),
        ("Graph controls with a tag condition", lambda r: r["a"].uses_tags),
        ("Graph controls with exposure or permissions and no finding input", lambda r: r["fix"] == FIX_CONTROL and (r["a"].uses_exposure or r["a"].uses_permissions)),
    ]
    classes = [stat(label, [r for r in graph if fn(r)]) for label, fn in class_defs]
    classes.append(stat("All graph controls", graph))
    classes.append(stat("Config rules acting as controls", [r for r in recs if r["cfg"]]))

    ranked = sorted(recs, key=lambda r: (-r["open"], r["name"]))
    with_open = [r for r in ranked if r["open"] > 0]
    concentration = []
    for n in (10, 20, 50, 100):
        top = sum(r["open"] for r in ranked[:n])
        concentration.append(["Top %d controls" % n, top, pct(top, total_open)])
    for target in (50, 80, 90):
        run, needed = 0, 0
        for r in with_open:
            run += r["open"]
            needed += 1
            if total_open and 100.0 * run / total_open >= target:
                break
        concentration.append(["Controls needed to reach %d%% of open Issues" % target, needed if total_open else 0, None])
    concentration.append(["Controls with at least one open Issue", len(with_open), pct(len(with_open), len(recs))])
    concentration.append(["Controls with no open Issue", len(recs) - len(with_open), pct(len(recs) - len(with_open), len(recs))])

    top_rows, cum = [], 0
    for i, r in enumerate(with_open[:25], 1):
        cum += r["open"]
        closed = r["resolved"] + r["rejected"]
        top_rows.append([i, r["name"], "Config rule as control" if r["cfg"] else ("Unknown" if r["synthetic"] else "Graph control"),
                         r["fix"], r["severity"], r["open"], pct(r["open"], total_open), pct(cum, total_open),
                         pct(r["rejected"], closed), r["fp"]])

    types = {}
    for r in graph:
        for t in r["a"].all_types:
            e = types.setdefault(t, {"controls": 0, "with_open": 0, "open": 0})
            e["controls"] += 1
            e["with_open"] += 1 if r["open"] > 0 else 0
            e["open"] += r["open"]
    type_rows = []
    for t, e in sorted(types.items(), key=lambda kv: (-kv[1]["open"], -kv[1]["controls"], kv[0])):
        if t in CCR_TYPES:
            treated = "CCR finding (rule level)"
        elif t in FINDING_TYPES or t.endswith("_FINDING"):
            treated = "Other finding type"
        elif t in EXPOSURE_TYPES:
            treated = "Exposure analysis"
        else:
            treated = "Resource / identity / other (not a finding)"
        type_rows.append([t, treated, e["controls"], e["with_open"], e["open"]])

    def share(rows, label_prefix):
        for row in rows:
            if row[0].startswith(label_prefix):
                return row
        return None

    b = dict((row[0], row) for row in buckets)
    def line(name):
        row = b.get(name)
        return "%s open (%s%%) from %s controls" % (row[4], row[5] if row[5] is not None else 0, row[1]) if row else "0"
    headlines = [
        "Open + in-progress Issues in workbook: %d across %d controls (%d controls have at least one)" % (total_open, len(recs), len(with_open)),
        "Config rules acting as controls: %s" % line(FIX_RULE_SINGLE),
        "Graph controls built on CCR findings: %s" % line(FIX_RULE_CCR),
        "Graph controls on other finding types: %s" % line(FIX_FINDING_OTHER),
        "Control level only: %s" % line(FIX_CONTROL),
        "Rule level combined: %s%% of open Issues. Any finding input: %s%%. Control level only: %s%%." % (rollups[0][5], rollups[1][5], rollups[4][5]),
        "Range for 'the fix is at the finding': %s%% (finding or rule is the only input) to %s%% (any finding input, including controls that also depend on exposure or permissions)." % (rollups[2][5], rollups[1][5]),
        "Concentration: top 10 controls = %s%%, top 20 = %s%%. %s controls reach 80%%." % (concentration[0][2], concentration[1][2], concentration[5][1]),
    ]
    return {"total_open": total_open, "buckets": buckets, "rollups": rollups, "classes": classes,
            "concentration": concentration, "top": top_rows, "types": type_rows, "headlines": headlines}


# --------------------------------------------------------------------------- #
# Workbook
# --------------------------------------------------------------------------- #

def write_workbook(path, control_rows, issue_rows, input_rows, evidence, args, run_info, list_counts, analysis):
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Alignment, Font, PatternFill, Border, Side
        from openpyxl.utils import get_column_letter
        from openpyxl.worksheet.datavalidation import DataValidation
        from openpyxl.formatting.rule import CellIsRule, FormulaRule
    except ImportError:
        raise WizAPIError("openpyxl is required for the workbook: pip install openpyxl")

    wb = Workbook()
    HEAD_FILL = PatternFill("solid", fgColor="1F3864")
    TRIAGE_FILL = PatternFill("solid", fgColor="7F6000")
    STAT_FILL = PatternFill("solid", fgColor="375623")
    QUERY_FILL = PatternFill("solid", fgColor="833C0B")
    INPUT_FILL = PatternFill("solid", fgColor="FFF2CC")
    HEAD_FONT = Font(bold=True, color="FFFFFF")
    thin = Side(style="thin", color="BFBFBF")
    BORDER = Border(left=thin, right=thin, top=thin, bottom=thin)

    def header(ws, headers, fills):
        for c, h in enumerate(headers, 1):
            cell = ws.cell(row=1, column=c, value=h)
            cell.font = HEAD_FONT
            cell.fill = fills[c - 1]
            cell.alignment = Alignment(wrap_text=True, vertical="center")
            cell.border = BORDER
        ws.row_dimensions[1].height = 42
        ws.freeze_panes = "C2"

    def widths(ws, headers, default=16, overrides=None):
        for c, h in enumerate(headers, 1):
            w = (overrides or {}).get(h, default)
            ws.column_dimensions[get_column_letter(c)].width = w

    # ---- README -------------------------------------------------------- #
    ws = wb.active
    ws.title = "README"
    readme = [
        ("Wiz Graph Control Triage Workbook", True),
        ("Generated %s by wiz_graph_control_triage.py v%s. Tenant %s, API %s." % (run_info["as_of"], VERSION, run_info.get("tenant", "?"), run_info.get("api_url", "?")), False),
        ("", False),
        ("How to use this workbook", True),
        ("1. Controls Review is the applicability decision, one row per Graph Control. Dark-blue columns are Wiz metadata, brown columns describe what the control's graph query correlates (parsed from Control.query), green columns are Issue statistics for the pull window, and gold columns are yours to fill.", False),
        ("2. Issues is the evidence. Each row is one Issue the control produced (all of them, or a per-control sample when --sample-per-control was used). Record the true/false-positive verdict per Issue, then roll the counts up into the control row (Sample Reviewed, True Positives, False Positives).", False),
        ("3. Control Inputs lists every entity type each control's query touches. Filter it on CONFIGURATION_FINDING to see which controls are built on Cloud Configuration Rule findings: a false positive there is fixed at the CCR, not at the control.", False),
        ("Analysis answers the scoping question with volume instead of control counts: how many open Issues come from config rules acting as controls, from graph controls built on CCR findings, from other finding types, and from control-level logic (exposure, permissions, properties). The Fix Location column on Controls Review is the same classification per control. It is derived from the control's query by entity type and property name, so check the Entity Types table at the bottom of Analysis before quoting a percentage.", False),
        ("Config rules acting as controls (Control Class = Config rule as control, Issue Type = CLOUD_CONFIGURATION) are single Cloud Configuration Rules that generate Issues with no correlation. They are included by default. Use --exclude-config-controls for graph controls only.", False),
        ("4. Work the controls in order of Open + In Progress (descending). Controls with zero Issues in the window still get a row so applicability can be recorded, but they are not where the noise is.", False),
        ("", False),
        ("Reading the Issue statistics", True),
        ("Reject Rate % and Rejected as FALSE_POSITIVE show how often teams have already rejected this control's Issues in the history window: a high rate is the strongest signal of a control that does not fit the estate.", False),
        ("OBJECT_DELETED % of Resolved shows churn: Issues that closed because the resource went away rather than because anyone fixed anything. Near 100 % on ephemeral workloads means the control measures deployment churn, not remediation.", False),
        ("Open With Ticket % and Open Past Due indicate whether the Issues are being worked at all. Zero tickets on hundreds of open Issues usually means the receiving team has stopped reading them.", False),
        ("Where a False Positive Gets Fixed is derived from the query: CCR-based controls are tuned at the rule, exposure/CIEM/vulnerability-based controls can only be adjusted at the control (clone + refine, scope, Ignore Rule).", False),
        ("", False),
        ("Drop-down meanings", True),
        ("Applicable at [ORG]?  Does the toxic combination this control describes make sense for this estate at all (technology in use, pattern not sanctioned by architecture).", False),
        ("Premise Holds Here?  Given compensating controls (WAF, private connectivity, ZTNA, SCPs), does the correlated risk still matter when the control fires.", False),
        ("Inputs Accurate?  Are the underlying findings/analysis the control relies on correct in this tenant (sample the Issues sheet).", False),
        ("Disposition -> Governance Outcome: Keep as-is / Rule validated; Scope by Project or BI, Ignore Rule -> B; Tune input rule -> B or D on the CCR; Clone and refine -> D; Disable Issue generation / Disable control -> C; Escalate -> E; Severity override -> F (last resort - tenant-global and moves compliance scores).", False),
        ("", False),
        ("Levers that exist in Wiz for a Graph Control (all tenant-global unless stated)", True),
        ("Enable/disable the control. Severity (tenant-global, avoid). Business Impact scoping (enabledForHBI/MBI/LBI/Unattributed) - runs the control only for Projects at those impact levels. Project scope (scopeProject) on custom controls. Issue generation toggle on the built-in control (keep the control, stop the Issues). Ignore Rules / Issue exceptions scoped to Projects, subscriptions, resources or tags. Duplicate the control and refine its graph query, then disable Issue generation on the built-in (custom-graph-controls pattern).", False),
        ("", False),
        ("Evidence", True),
        ("Every count on Controls Review is computed client-side from the Issues pulled with the filters recorded on the Summary sheet; re-run the same filter in the Wiz console to reproduce a number. The API issueAnalytics.issueCount column is Wiz's own count for cross-checking (selection recorded on Summary).", False),
        ("Issues auto-resolve when the toxic combination disappears (~24 h), REJECTED Issues carry WONT_FIX / EXCEPTION / FALSE_POSITIVE, and history outside the --history-days window is not included.", False),
    ]
    for i, (text, bold) in enumerate(readme, 1):
        c = ws.cell(row=i, column=1, value=text.replace("[ORG]", args.org))
        c.font = Font(bold=bold, size=12 if bold else 11)
        c.alignment = Alignment(wrap_text=True, vertical="top")
    ws.column_dimensions["A"].width = 160

    # ---- Lists (drop-down sources) ------------------------------------- #
    wl = wb.create_sheet("Lists")
    list_ranges = {}
    for col, (key, values) in enumerate(LISTS.items(), 1):
        wl.cell(row=1, column=col, value=key).font = Font(bold=True)
        for r, v in enumerate(values, 2):
            wl.cell(row=r, column=col, value=v)
        letter = get_column_letter(col)
        list_ranges[key] = "Lists!$%s$2:$%s$%d" % (letter, letter, len(values) + 1)
        wl.column_dimensions[letter].width = 44
    wl.sheet_state = "hidden"

    # ---- Controls Review ------------------------------------------------ #
    wc = wb.create_sheet("Controls Review")
    base_headers = list(control_rows[0].keys()) if control_rows else list(control_row({}, None, analyse_query(None), {}, args, None).keys())
    triage_cols = OrderedDict((h.replace("[ORG]", args.org), v) for h, v in TRIAGE_CONTROL_COLUMNS.items())
    triage_headers = list(triage_cols.keys())
    headers = base_headers + triage_headers
    query_start = base_headers.index("Root Entity Type(s)")
    stat_start = base_headers.index("Open Issues")
    fills = []
    for i, h in enumerate(headers):
        if i >= len(base_headers):
            fills.append(TRIAGE_FILL)
        elif i >= stat_start:
            fills.append(STAT_FILL)
        elif i >= query_start:
            fills.append(QUERY_FILL)
        else:
            fills.append(HEAD_FILL)
    header(wc, headers, fills)
    for r, row in enumerate(control_rows, 2):
        for c, h in enumerate(base_headers, 1):
            cell = wc.cell(row=r, column=c, value=clean(row.get(h)))
            cell.border = BORDER
            if h in ("Description", "Resolution Recommendation", "Where a False Positive Gets Fixed"):
                cell.alignment = Alignment(wrap_text=True, vertical="top")
        for c in range(len(base_headers) + 1, len(headers) + 1):
            cell = wc.cell(row=r, column=c)
            cell.fill = INPUT_FILL
            cell.border = BORDER
    n_rows = max(2, len(control_rows) + 1)
    for h, list_key in triage_cols.items():
        if not list_key:
            continue
        col = get_column_letter(headers.index(h) + 1)
        dv = DataValidation(type="list", formula1="=" + list_ranges[list_key], allow_blank=True,
                            showErrorMessage=True, errorTitle="Pick from list", error="Choose a value from the drop-down")
        dv.add("%s2:%s%d" % (col, col, n_rows))
        wc.add_data_validation(dv)
    for h in ("Sample Reviewed (n)", "True Positives (n)", "False Positives (n)", "Needs Info (n)"):
        col = get_column_letter(headers.index(h) + 1)
        dv = DataValidation(type="whole", operator="greaterThanOrEqual", formula1="0", allow_blank=True)
        dv.add("%s2:%s%d" % (col, col, n_rows))
        wc.add_data_validation(dv)
    sev_col = get_column_letter(headers.index("Severity") + 1)
    sev_rng = "%s2:%s%d" % (sev_col, sev_col, n_rows)
    for val, color in (("CRITICAL", "C00000"), ("HIGH", "ED7D31"), ("MEDIUM", "FFC000")):
        wc.conditional_formatting.add(sev_rng, CellIsRule(operator="equal", formula=['"%s"' % val], fill=PatternFill("solid", fgColor=color)))
    rej_col = get_column_letter(headers.index("Reject Rate % (rejected / closed)") + 1)
    wc.conditional_formatting.add("%s2:%s%d" % (rej_col, rej_col, n_rows),
                                  CellIsRule(operator="greaterThanOrEqual", formula=["25"], fill=PatternFill("solid", fgColor="F8CBAD")))
    od_col = get_column_letter(headers.index("OBJECT_DELETED % of Resolved") + 1)
    wc.conditional_formatting.add("%s2:%s%d" % (od_col, od_col, n_rows),
                                  CellIsRule(operator="greaterThanOrEqual", formula=["80"], fill=PatternFill("solid", fgColor="F8CBAD")))
    wc.auto_filter.ref = "A1:%s%d" % (get_column_letter(len(headers)), n_rows)
    widths(wc, headers, 14, {
        "Control ID": 38, "Control Name": 58, "Description": 60, "Resolution Recommendation": 50,
        "Frameworks": 30, "Categories": 40, "All Entity Types in Query": 40, "Finding-Type Inputs": 30,
        "Input Classes": 30, "Referenced CCRs": 40, "Relationship Types": 30, "Where Keys": 40,
        "Where a False Positive Gets Fixed": 70, "Top Projects (open)": 40, "Resolution Reason Mix": 36,
        "Rejection Reason Mix": 30, "Compensating Controls": 36, "Notes / Evidence": 50, "Disposition": 34,
        "Governance Outcome": 34, "Primary FP Cause": 34, "Inputs Accurate?": 30, "Applicable at %s?" % args.org: 34,
        "Open Entity Types": 30, "Business Impact Scope": 22, "Tags": 24,
    })

    # ---- Issues --------------------------------------------------------- #
    wi = wb.create_sheet("Issues")
    ibase = list(issue_rows[0].keys()) if issue_rows else list(issue_row({"entitySnapshot": {}}, args.app_url).keys())
    iheaders = ibase + list(TRIAGE_ISSUE_COLUMNS.keys())
    header(wi, iheaders, [HEAD_FILL] * len(ibase) + [TRIAGE_FILL] * len(TRIAGE_ISSUE_COLUMNS))
    for r, row in enumerate(issue_rows, 2):
        for c, h in enumerate(ibase, 1):
            v = clean(row.get(h))
            cell = wi.cell(row=r, column=c, value=v)
            if h in ("Issue Link", "Entity Link", "Ticket URL", "Cloud Console URL") and v:
                cell.hyperlink = v
                cell.font = Font(color="0563C1", underline="single")
        for c in range(len(ibase) + 1, len(iheaders) + 1):
            wi.cell(row=r, column=c).fill = INPUT_FILL
    ni = max(2, len(issue_rows) + 1)
    for h, list_key in TRIAGE_ISSUE_COLUMNS.items():
        if not list_key:
            continue
        col = get_column_letter(iheaders.index(h) + 1)
        dv = DataValidation(type="list", formula1="=" + list_ranges[list_key], allow_blank=True)
        dv.add("%s2:%s%d" % (col, col, ni))
        wi.add_data_validation(dv)
    isev = get_column_letter(iheaders.index("Severity") + 1)
    for val, color in (("CRITICAL", "C00000"), ("HIGH", "ED7D31"), ("MEDIUM", "FFC000")):
        wi.conditional_formatting.add("%s2:%s%d" % (isev, isev, ni), CellIsRule(operator="equal", formula=['"%s"' % val], fill=PatternFill("solid", fgColor=color)))
    wi.auto_filter.ref = "A1:%s%d" % (get_column_letter(len(iheaders)), ni)
    widths(wi, iheaders, 14, {"Issue ID": 38, "Control ID": 38, "Control Name": 50, "Entity Name": 40,
                              "Entity Tags": 30, "All Projects": 30, "Primary Project": 26, "Issue Link": 20,
                              "Which Input Is Wrong": 36, "Notes / Evidence": 50, "FP Cause": 34,
                              "Recommended Action": 24, "Verdict": 26, "Cloud Console URL": 20})

    # ---- Control Inputs ------------------------------------------------- #
    wn = wb.create_sheet("Control Inputs")
    nheaders = ["Control ID", "Control Name", "Enabled", "Severity", "Open + In Progress", "Entity Type",
                "Role", "Finding Type?", "Finding Description", "Negated?", "Optional?", "Where Keys on This Type",
                "Referenced CCRs"]
    header(wn, nheaders, [HEAD_FILL] * len(nheaders))
    for r, row in enumerate(input_rows, 2):
        for c, h in enumerate(nheaders, 1):
            wn.cell(row=r, column=c, value=clean(row.get(h)))
    wn.auto_filter.ref = "A1:%s%d" % (get_column_letter(len(nheaders)), max(2, len(input_rows) + 1))
    widths(wn, nheaders, 16, {"Control ID": 38, "Control Name": 55, "Entity Type": 30, "Finding Description": 36,
                              "Where Keys on This Type": 40, "Referenced CCRs": 40})

    # ---- Summary -------------------------------------------------------- #
    wsu = wb.create_sheet("Summary", 1)
    rows = [
        ("Run", ""),
        ("Generated (UTC)", run_info["as_of"]),
        ("Script", "wiz_graph_control_triage.py v%s" % VERSION),
        ("API endpoint", run_info.get("api_url")),
        ("Tenant id (JWT tid)", run_info.get("tenant")),
        ("Service account (JWT name)", run_info.get("sa_name")),
        ("Requests made", run_info.get("requests")),
        ("Duration (s)", run_info.get("duration")),
        ("", ""),
        ("Controls", ""),
        ("controls totalCount (API)", (evidence.get("controls") or {}).get("totalCount")),
        ("controls fetched", (evidence.get("controls") or {}).get("fetched")),
        ("Controls in workbook", list_counts.get("controls_rows")),
        ("  of which enabled", list_counts.get("controls_enabled")),
        ("  of which built-in", list_counts.get("controls_builtin")),
        ("  of which custom", list_counts.get("controls_custom")),
        ("  with open/in-progress Issues", list_counts.get("controls_with_open")),
        ("  graph controls built on CCR findings", list_counts.get("controls_ccr")),
        ("  config rules acting as controls (type CLOUD_CONFIGURATION), included", list_counts.get("controls_config")),
        ("  config rules acting as controls, excluded (--exclude-config-controls)", list_counts.get("controls_excluded_config")),
        ("  placeholder rows (control referenced by Issues but not returned by the controls query)", list_counts.get("controls_synthetic")),
        ("Pruned Control fields (not in this tenant's schema)", ", ".join((evidence.get("controls") or {}).get("pruned") or []) or "none"),
        ("Control selection used", (evidence.get("controls") or {}).get("selection")),
        ("issueAnalytics selection", evidence.get("issueAnalytics_selection", "n/a")),
        ("ControlIssueAnalyticsSelection input fields", evidence.get("issueAnalytics_input_fields", "n/a")),
        ("", ""),
        ("Issues", ""),
    ]
    for label, sc in ((evidence.get("issues") or {}).get("scopes") or {}).items():
        rows.append(("issuesV2 filter [%s]" % label, json.dumps(sc["filter"])))
        rows.append(("  totalCount (API) / fetched / pages", "%s / %s / %s%s" % (sc["totalCount"], sc["fetched"], sc["pages"],
                                                                               ("  ERROR: " + sc["error"]) if sc.get("error") else "")))
    rows += [
        ("Unique Issues pulled", (evidence.get("issues") or {}).get("unique")),
        ("Issue rows written (sampling: %s)" % ("all" if not args.sample_per_control else "%d per control" % args.sample_per_control), list_counts.get("issue_rows")),
        ("Sampling note", evidence.get("auto_sample", "none")),
        ("Issues whose control is not in the controls pull", list_counts.get("orphan_issues")),
        ("Pruned Issue fields", ", ".join((evidence.get("issues") or {}).get("pruned") or []) or "none"),
        ("", ""),
        ("Cloud Configuration Rules (for CCR reference resolution)", json.dumps(evidence.get("ccr") or {"status": "not needed / skipped"})),
        ("", ""),
        ("Triage progress (live formulas)", ""),
    ]
    for i, (k, v) in enumerate(rows, 1):
        a = wsu.cell(row=i, column=1, value=k)
        b = wsu.cell(row=i, column=2, value=clean(v))
        if v == "" and k:
            a.font = Font(bold=True, size=12)
        b.alignment = Alignment(wrap_text=True, vertical="top")
    start = len(rows) + 1
    disp_col = get_column_letter(headers.index("Disposition") + 1)
    appl_col = get_column_letter(headers.index("Applicable at %s?" % args.org) + 1)
    verdict_col = get_column_letter(iheaders.index("Verdict") + 1)
    progress = [
        ("Controls with a Disposition", "=COUNTA('Controls Review'!%s2:%s%d)" % (disp_col, disp_col, n_rows)),
        ("Controls marked not applicable", "=COUNTIF('Controls Review'!%s2:%s%d,\"No*\")" % (appl_col, appl_col, n_rows)),
        ("Controls to disable (either disable option)", "=COUNTIF('Controls Review'!%s2:%s%d,\"Disable*\")" % (disp_col, disp_col, n_rows)),
        ("Controls to tune at the CCR", "=COUNTIF('Controls Review'!%s2:%s%d,\"Tune input*\")" % (disp_col, disp_col, n_rows)),
        ("Controls to clone and refine", "=COUNTIF('Controls Review'!%s2:%s%d,\"Clone*\")" % (disp_col, disp_col, n_rows)),
        ("Issues with a verdict", "=COUNTA(Issues!%s2:%s%d)" % (verdict_col, verdict_col, ni)),
        ("Issues marked false positive", "=COUNTIF(Issues!%s2:%s%d,\"False positive\")" % (verdict_col, verdict_col, ni)),
        ("Issues marked true positive", "=COUNTIF(Issues!%s2:%s%d,\"True positive\")" % (verdict_col, verdict_col, ni)),
    ]
    for j, (k, f) in enumerate(progress):
        wsu.cell(row=start + j, column=1, value=k)
        wsu.cell(row=start + j, column=2, value=f)
    wsu.column_dimensions["A"].width = 58
    wsu.column_dimensions["B"].width = 120

    # ---- Analysis -------------------------------------------------------- #
    wa = wb.create_sheet("Analysis", 2)
    state = {"r": 1}

    def a_title(text, size=12):
        wa.cell(row=state["r"], column=1, value=text).font = Font(bold=True, size=size)
        state["r"] += 1

    def a_note(text):
        c = wa.cell(row=state["r"], column=1, value=text.replace("[ORG]", args.org))
        c.alignment = Alignment(wrap_text=True, vertical="top")
        wa.merge_cells(start_row=state["r"], start_column=1, end_row=state["r"], end_column=11)
        wa.row_dimensions[state["r"]].height = 15 * max(1, (len(text) // 150) + 1)
        state["r"] += 1

    def a_table(hdrs, data, bold_last=0):
        for c, h in enumerate(hdrs, 1):
            cell = wa.cell(row=state["r"], column=c, value=h)
            cell.font = HEAD_FONT
            cell.fill = HEAD_FILL
            cell.alignment = Alignment(wrap_text=True, vertical="center")
            cell.border = BORDER
        wa.row_dimensions[state["r"]].height = 32
        state["r"] += 1
        for i, row in enumerate(data):
            for c, v in enumerate(row, 1):
                cell = wa.cell(row=state["r"], column=c, value=clean(v) if v is not None else "")
                cell.border = BORDER
                if bold_last and i >= len(data) - bold_last:
                    cell.font = Font(bold=True)
            state["r"] += 1
        state["r"] += 1

    a_title("Where the fix belongs, measured by Issue volume", 14)
    a_note("Generated %s. Open = OPEN + IN_PROGRESS. Window = Issues resolved or rejected in the last %s days. Percentages are of the %d open Issues in this workbook." % (run_info["as_of"], args.history_days, analysis["total_open"]))
    state["r"] += 1
    a_title("Headlines")
    for h in analysis["headlines"]:
        a_note(h)
    state["r"] += 1
    a_title("1. Fix location (each control counted once)")
    a_note("Rule level = a false positive is corrected at a Cloud Configuration Rule and the control inherits it. Finding level = the control keys on vulnerability, secret, data or malware findings handled under their own programme. Control level = the control correlates exposure, permissions or resource properties and can only be adjusted at the control (scope, Ignore Rule, clone and refine, disable).")
    a_table(ANALYSIS_HEADERS, analysis["buckets"], bold_last=1)
    a_title("2. Roll-ups")
    a_note("The 'only input' row is the conservative figure for work that belongs at the finding or rule. The 'combined' row is toxic combinations in the full sense: a finding plus exposure or permissions, where a false positive can come from either side and the control still has to be judged.")
    a_table(ANALYSIS_HEADERS, analysis["rollups"])
    a_title("3. Input classes (a control can appear in several rows)")
    a_table(ANALYSIS_HEADERS, analysis["classes"], bold_last=2)
    a_title("4. Concentration of open Issues")
    a_table(["Measure", "Value", "%"], analysis["concentration"])
    a_title("5. Top 25 controls by open Issues")
    a_table(["Rank", "Control", "Control Class", "Fix Location", "Severity", "Open + In Progress", "% of Open Issues",
             "Cumulative %", "Reject Rate %", "Rejected as FALSE_POSITIVE"], analysis["top"])
    a_title("6. Entity types seen in graph control queries (audit of the classification)")
    a_note("Every entity type that appears in any graph control query, and how this script treats it. If a type listed as 'Resource / identity / other' is really a finding type in this tenant, the Fix Location of the controls using it is understated: report the type so it can be added.")
    a_table(["Entity Type", "Treated As", "Controls Using It", "Of Which With Open Issues", "Open Issues of Those Controls"], analysis["types"])
    wa.column_dimensions["A"].width = 78
    wa.column_dimensions["B"].width = 44
    wa.column_dimensions["C"].width = 24
    wa.column_dimensions["D"].width = 52
    for col in "EFGHIJK":
        wa.column_dimensions[col].width = 18

    wb.save(path)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def csv_list(value):
    return [v.strip() for v in value.split(",") if v.strip()] if value else []


def parse_args(argv=None):
    p = argparse.ArgumentParser(description="Export Wiz Graph Controls and their Issues into a triage workbook.",
                                formatter_class=argparse.RawDescriptionHelpFormatter,
                                epilog=__doc__.split("Usage:")[1] if "Usage:" in __doc__ else "")
    p.add_argument("-o", "--output", default=None, help="Output .xlsx path (default Wiz_Graph_Control_Triage_<UTC date>.xlsx)")
    p.add_argument("--dry-run", action="store_true", help="Authenticate, introspect, report totalCounts; write nothing")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("--statuses", default="OPEN,IN_PROGRESS", help="Issue statuses for the current view (default OPEN,IN_PROGRESS)")
    p.add_argument("--history-days", type=int, default=180, help="Also pull RESOLVED/REJECTED Issues whose status changed in the last N days (default 180; 0 = skip)")
    p.add_argument("--issue-types", default="TOXIC_COMBINATION,CLOUD_CONFIGURATION", help="Issue types to pull, one pull per type (default TOXIC_COMBINATION,CLOUD_CONFIGURATION)")
    p.add_argument("--severity", default=None, help="Issue severity filter, e.g. CRITICAL,HIGH")
    p.add_argument("--project", default=None, help="Wiz project id(s) to restrict Issues to (comma-separated)")
    p.add_argument("--exclude-config-controls", action="store_true", help="Leave out config rules acting as controls (type CLOUD_CONFIGURATION) and their Issues")
    p.add_argument("--include-config-controls", action="store_true", help=argparse.SUPPRESS)  # default since 1.1.0
    p.add_argument("--max-issue-rows", type=int, default=300000, help="If more Issues than this are pulled and no --sample-per-control is set, write a 200-per-control sample (statistics still use every Issue)")
    p.add_argument("--enabled-only", action="store_true", help="Only controls that are enabled")
    p.add_argument("--with-issues-only", action="store_true", help="Only controls with at least one Issue in the pull window")
    p.add_argument("--sample-per-control", type=int, default=0, help="Write at most N Issues per control to the Issues sheet (0 = all)")
    p.add_argument("--no-ccr-resolve", action="store_true", help="Do not pull cloudConfigurationRules to resolve CCR ids referenced by control queries")
    p.add_argument("--app-url", default=os.environ.get("WIZ_APP_URL", DEFAULT_APP_URL), help="Console base URL for deep links (default %s)" % DEFAULT_APP_URL)
    p.add_argument("--org", default="[ORG]", help="Organisation name used in triage column headers (default [ORG])")
    p.add_argument("--page-size", type=int, default=500)
    p.add_argument("--raw-dir", default=None, help="Also dump raw JSON (controls.json, issues.json) into this directory")
    p.add_argument("--auth-url", default=os.environ.get("WIZ_AUTH_URL", DEFAULT_AUTH_URL))
    p.add_argument("--audience", default=os.environ.get("WIZ_AUDIENCE", "wiz-api"))
    p.add_argument("--ca-bundle", default=None, help="Corporate CA bundle path for TLS verification")
    p.add_argument("--no-introspection", action="store_true", help="Skip schema introspection (error-driven pruning only)")
    p.add_argument("--pause", type=float, default=0.25, help="Seconds to sleep between API calls (tenant pool is 10 q/s)")
    args = p.parse_args(argv)
    args.statuses = csv_list(args.statuses)
    args.issue_types = csv_list(args.issue_types)
    if args.exclude_config_controls:
        args.issue_types = [t for t in args.issue_types if t != "CLOUD_CONFIGURATION"] or ["TOXIC_COMBINATION"]
    args.severity = csv_list(args.severity) if args.severity else None
    args.project = csv_list(args.project) if args.project else None
    return args


def main(argv=None):
    args = parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s", datefmt="%H:%M:%S")
    client_id = os.environ.get("WIZ_CLIENT_ID")
    client_secret = os.environ.get("WIZ_CLIENT_SECRET")
    if not client_id and sys.stdin.isatty():
        client_id = input("WIZ_CLIENT_ID: ").strip()
    if not client_secret and sys.stdin.isatty():
        client_secret = getpass.getpass("WIZ_CLIENT_SECRET: ")
    if not client_id or not client_secret:
        log.error("WIZ_CLIENT_ID and WIZ_CLIENT_SECRET must be set in the environment")
        return 1
    started = time.time()
    as_of = datetime.now(timezone.utc)
    client = WizClient(args.auth_url, os.environ.get("WIZ_API_URL"), client_id, client_secret,
                       audience=args.audience, verify=args.ca_bundle or True, pause=args.pause)
    evidence = {}
    exit_code = 0
    try:
        client.ensure_api_url()
        explorer = SchemaExplorer(client, enabled=not args.no_introspection)
        explorer.probe()
        if explorer.available and not explorer.has_root("controls"):
            raise WizAPIError("`controls` root not visible to this service account (needs read:controls)")

        if args.dry_run:
            log.info("DRY RUN: counting only")
            pruned = []
            spec = OrderedDict([("id", None)])
            _, total_c, _ = paged_fetch(client, "controls", spec, 1, "controls(count)", pruned, filter_by={}, filter_type="ControlFilters", max_pages=1)
            log.info("controls totalCount = %s", total_c)
            grand = 0
            for itype in args.issue_types:
                flts = [("current", {"type": [itype], "status": args.statuses})]
                if args.history_days:
                    flts.append(("history", {"type": [itype], "status": ["RESOLVED", "REJECTED"],
                                             "statusChangedAt": {"after": iso_z(as_of - timedelta(days=args.history_days))}}))
                for label, flt in flts:
                    try:
                        _, total_i, _ = paged_fetch(client, "issuesV2", OrderedDict([("id", None)]), 1, "issues(count %s %s)" % (label, itype),
                                                    pruned, filter_by=flt, filter_type="IssueFilters", max_pages=1)
                    except WizPermissionError:
                        raise
                    except WizAPIError as exc:
                        log.warning("issuesV2 %s could not be counted: %s", json.dumps(flt), str(exc)[:200])
                        continue
                    grand += total_i or 0
                    log.info("issuesV2 %s totalCount = %s", json.dumps(flt), total_i)
            log.info("Estimated full run: %d Issues, ~%d issue pages + ~%d control pages", grand,
                     (grand // args.page_size) + len(args.issue_types) * 2, ((total_c or 0) // args.page_size) + 1)
            if grand > args.max_issue_rows:
                log.info("More than --max-issue-rows (%d) Issues: the Issues sheet will be a 200-per-control sample unless you set --sample-per-control", args.max_issue_rows)
            if explorer.available:
                node_t = explorer.node_type_of("controls")
                have = explorer.type_fields(node_t) if node_t else {}
                missing = [f for f in CONTROL_SPEC if f not in have] if have else []
                log.info("Control node type %s; Control fields absent in this tenant: %s", node_t, ", ".join(missing) or "none")
                log.info("issueAnalytics on Control: %s", "yes" if "issueAnalytics" in have else "no")
            log.info("Dry run complete in %.1fs (%d requests)", time.time() - started, client.requests_made)
            return 0

        controls = pull_controls(client, explorer, args, evidence)
        issues = pull_issues(client, explorer, args, as_of, evidence)
        if (evidence.get("issues") or {}).get("failed"):
            exit_code = 2

        # -- analyse queries, collect CCR references
        analyses = {}
        wanted_rule_ids = set()
        for c in controls:
            a = analyse_query(c.get("query"))
            analyses[c["id"]] = a
            wanted_rule_ids |= a.rule_ids
        ccr_map = pull_ccrs(client, explorer, args, evidence, wanted_rule_ids)
        if ccr_map is None:
            exit_code = 2
            ccr_map = {}

        # -- aggregate
        per = aggregate(controls, issues, as_of, args)
        control_ids = {c["id"] for c in controls}
        orphan = sum(len(v["issues"]) for k, v in per.items() if k not in control_ids)

        # -- select controls
        selected = []
        excluded_config = 0
        for c in controls:
            if args.exclude_config_controls and is_config_control(c):
                excluded_config += 1
                continue
            if args.enabled_only and not c.get("enabled"):
                continue
            if args.with_issues_only and c["id"] not in per:
                continue
            selected.append(c)
        # Synthetic rows for issues whose control was not returned (deleted control, CCR-as-control, etc.)
        for cid, agg in per.items():
            if cid in control_ids or cid == "unknown":
                continue
            if args.exclude_config_controls and cid.startswith("ccr:"):
                continue
            selected.append({"id": cid, "name": agg["name"] or cid, "type": "(not returned by controls query)",
                             "enabled": None, "severity": None, "createdBy": {}, "_synthetic": True})
            analyses[cid] = analyse_query(None)

        pulled_total = sum(len(v["issues"]) for v in per.values())
        if not args.sample_per_control and pulled_total > args.max_issue_rows:
            args.sample_per_control = 200
            evidence["auto_sample"] = ("%d Issues pulled exceeds --max-issue-rows %d: Issues sheet holds a 200-per-control sample. "
                                       "All statistics use every Issue." % (pulled_total, args.max_issue_rows))
            log.warning(evidence["auto_sample"])
        issue_rows_src = select_issue_rows(per, args)
        control_rows = []
        for c in selected:
            agg = per.get(c["id"])
            row = control_row(c, agg, analyses[c["id"]], ccr_map, args, as_of)
            row["Issues Rows in Workbook"] = (agg or {}).get("sampled", len((agg or {}).get("issues", []))) if agg else 0
            control_rows.append(row)
        control_rows.sort(key=lambda r: (-(r["Open + In Progress"] or 0), -(r["Rejected (window)"] or 0), r["Control Name"] or ""))

        input_rows = []
        for c in selected:
            a = analyses[c["id"]]
            agg = per.get(c["id"])
            ccr_refs = "; ".join(((ccr_map.get(r) or {}).get("shortId") or r) for r in sorted(a.rule_ids))
            if is_config_control(c) and not a.all_types:
                src = c.get("sourceCloudConfigurationRule") if isinstance(c.get("sourceCloudConfigurationRule"), dict) else {}
                input_rows.append(OrderedDict([
                    ("Control ID", c["id"]), ("Control Name", c.get("name")), ("Enabled", c.get("enabled")),
                    ("Severity", c.get("severity")),
                    ("Open + In Progress", (agg["open"] + agg["in_progress"]) if agg else 0),
                    ("Entity Type", "CONFIGURATION_FINDING"), ("Role", "Config rule as control (single rule)"),
                    ("Finding Type?", "Yes"), ("Finding Description", FINDING_TYPES["CONFIGURATION_FINDING"]),
                    ("Negated?", False), ("Optional?", False), ("Where Keys on This Type", ""),
                    ("Referenced CCRs", ("%s %s" % (src.get("shortId") or "", src.get("name") or "")).strip()),
                ]))
            for t, info in a.all_types.items():
                input_rows.append(OrderedDict([
                    ("Control ID", c["id"]), ("Control Name", c.get("name")), ("Enabled", c.get("enabled")),
                    ("Severity", c.get("severity")),
                    ("Open + In Progress", (agg["open"] + agg["in_progress"]) if agg else 0),
                    ("Entity Type", t), ("Role", "Root / selected" if info["depth"] == 0 else "Related (depth %d)" % info["depth"]),
                    ("Finding Type?", "Yes" if (t in FINDING_TYPES or t.endswith("_FINDING")) else "No"),
                    ("Finding Description", FINDING_TYPES.get(t, "")),
                    ("Negated?", info["negated"]), ("Optional?", info["optional"]),
                    ("Where Keys on This Type", ", ".join(sorted(info["where_keys"]))),
                    ("Referenced CCRs", ccr_refs if t in ("CONFIGURATION_FINDING", "CONFIGURATION_RULE") else ""),
                ]))
        selected_ids = {c["id"] for c in selected}
        issue_rows = [issue_row(i, args.app_url) for i in issue_rows_src if i.get("_control_id") in selected_ids]
        issue_rows.sort(key=lambda r: (r["Control Name"] or "", {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(r["Severity"], 9), -(r["Age (days)"] or 0)))

        list_counts = {
            "controls_rows": len(control_rows),
            "controls_enabled": sum(1 for c in selected if c.get("enabled")),
            "controls_builtin": sum(1 for c in selected if origin_of(c) == "Built-in" and not c.get("_synthetic")),
            "controls_custom": sum(1 for c in selected if origin_of(c) == "Custom" and not c.get("_synthetic")),
            "controls_with_open": sum(1 for r in control_rows if (r["Open + In Progress"] or 0) > 0),
            "controls_ccr": sum(1 for r in control_rows if r["Built on CCR Findings?"] == "Yes"),
            "controls_excluded_config": excluded_config,
            "controls_config": sum(1 for c in selected if is_config_control(c)),
            "controls_synthetic": sum(1 for c in selected if c.get("_synthetic")),
            "issue_rows": len(issue_rows),
            "orphan_issues": orphan,
        }
        run_info = {"as_of": iso_z(as_of), "api_url": client.api_url, "tenant": client.token_claims.get("tid"),
                    "sa_name": client.token_claims.get("name"), "requests": client.requests_made,
                    "duration": round(time.time() - started, 1)}
        out = args.output or "Wiz_Graph_Control_Triage_%s.xlsx" % as_of.strftime("%Y-%m-%d")
        analysis = build_analysis(selected, per, analyses)
        write_workbook(out, control_rows, issue_rows, input_rows, evidence, args, run_info, list_counts, analysis)
        log.info("Workbook written: %s (%d control rows, %d issue rows, %d input rows)", out, len(control_rows), len(issue_rows), len(input_rows))
        log.info("---- Headlines (also on the Analysis sheet) ----")
        for h in analysis["headlines"]:
            log.info("  %s", h)

        if args.raw_dir:
            os.makedirs(args.raw_dir, exist_ok=True)
            with open(os.path.join(args.raw_dir, "controls.json"), "w") as fh:
                json.dump(controls, fh, indent=1, default=str)
            with open(os.path.join(args.raw_dir, "issues.json"), "w") as fh:
                json.dump([{k: v for k, v in i.items() if not k.startswith("_")} for i in issues], fh, indent=1, default=str)
            with open(os.path.join(args.raw_dir, "evidence.json"), "w") as fh:
                json.dump({"evidence": evidence, "run": run_info, "counts": list_counts,
                           "analysis": {k: v for k, v in analysis.items()}}, fh, indent=1, default=str)
            log.info("Raw JSON written to %s", args.raw_dir)
        if orphan:
            log.warning("%d Issues reference a control that the controls query did not return (synthetic rows added)", orphan)
        if (evidence.get("controls") or {}).get("pruned"):
            log.info("Control fields pruned for this tenant: %s", ", ".join(evidence["controls"]["pruned"]))
        return exit_code
    except WizPermissionError as exc:
        log.error("Permission error - check service-account scopes (read:controls, read:issues, read:cloud_configuration_rule): %s", exc)
        return 1
    except WizAPIError as exc:
        log.error("%s", exc)
        return 1
    except KeyboardInterrupt:
        log.error("Interrupted")
        return 1


if __name__ == "__main__":
    sys.exit(main())
