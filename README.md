# wiz_graph_control_triage.py — Graph Control applicability and false-positive triage

Exports every Graph Control in a Wiz tenant plus the Issues those controls generated, and writes one
Excel workbook with two review levels: the control (is this toxic combination applicable here, and
which lever fixes it) and the Issue (is this instance a true or false positive). Built on the same
client, introspection and pruning pattern as the other scripts in the wiz-expert bundle.

Version 1.0.0 — mock-tested only (`tests_mock_wiz_gc.py`, four configurations). First live run:
`--dry-run -v`, then a full run, then record real schema findings back into `api-reference.md`.

## Service account

Custom Integration (GraphQL API), read-only scopes:

| Scope | Used for | Required |
|---|---|---|
| `read:controls` | `controls` root (control metadata, `query`, BI flags, `issueAnalytics`) | yes |
| `read:issues` | `issuesV2` (WIN API, schema-stable) | yes |
| `read:cloud_configuration_rule` (legacy `read:cloud_configuration`) | resolves CCR ids referenced by control queries to short IDs (EC2-022 …) | optional — FORBIDDEN degrades to exit 2 |

Credentials only via environment variables. `WIZ_API_URL` is optional: the script derives the
data center from the token's `dc` claim (wrong DC is the classic 401 UNAUTHORIZED).

```bash
export WIZ_CLIENT_ID=…  WIZ_CLIENT_SECRET=…
export WIZ_API_URL=https://api.usXX.app.wiz.io/graphql     # optional
pip install requests openpyxl

python3 wiz_graph_control_triage.py --dry-run -v                       # counts, schema, estimate
python3 wiz_graph_control_triage.py --org "S&P" -o spg_gc_triage.xlsx  # full export
python3 wiz_graph_control_triage.py --org "S&P" --history-days 180 --sample-per-control 25 -o spg_gc_triage.xlsx
```

## What is pulled

1. `controls` — all Graph Controls (enabled and disabled). Controls of type `CLOUD_CONFIGURATION`
   (the config-rule-as-control duplicates) are excluded unless `--include-config-controls`.
2. `issuesV2` — two scopes, de-duplicated by id:
   * current: `type: TOXIC_COMBINATION`, `status: OPEN, IN_PROGRESS` (change with `--statuses`, `--severity`, `--project`, `--issue-types`)
   * history: `status: RESOLVED, REJECTED` with `statusChangedAt` in the last `--history-days` (default 90, 0 to skip)
3. `cloudConfigurationRules` — only when a control query references CCR ids (skip with `--no-ccr-resolve`).

Every filter and `totalCount` lands on the Summary sheet so any number can be reproduced in the console.

## Workbook

| Sheet | Content |
|---|---|
| README | How to triage, column meanings, drop-down meanings, the Wiz levers that exist for a Graph Control |
| Summary | Run evidence: endpoint, tenant id, filters, totalCounts, pruned fields, counts, live progress formulas |
| Controls Review | One row per control. Blue = Wiz metadata (origin, enabled, severity, Business Impact scope, project scope, frameworks). Brown = what the control's graph query correlates: root and related entity types, finding-type inputs, Built on CCR Findings?, referenced CCRs, exposure / CIEM / vulnerability / sensitive-data / tag conditions, negated relationships, and "Where a False Positive Gets Fixed". Green = Issue statistics for the window: open / in progress, severity split, unique entities, oldest and median age, past due, ticket %, top projects, clouds, subscriptions, resolved / rejected, resolution-reason mix, rejected as FALSE_POSITIVE, reject rate, OBJECT_DELETED % of resolved, median days-to-resolve, Wiz's own `issueAnalytics.issueCount` for cross-check. Gold = triage columns with drop-downs. |
| Issues | One row per Issue (all, or `--sample-per-control N`, which prefers open Issues spread across projects and adds a slice of rejected/resolved history). Entity, project, business impact, age, due, ticket, console deep links, plus Verdict / FP Cause / Which Input Is Wrong / Recommended Action. |
| Control Inputs | One row per (control, entity type in its query). Filter on `CONFIGURATION_FINDING` to list every control that is a correlation of Cloud Configuration Rule findings. |
| Lists | Hidden drop-down sources. |

Controls are sorted by Open + In Progress descending. Reject Rate ≥ 25 % and OBJECT_DELETED ≥ 80 %
are highlighted — the first is the strongest "does not fit the estate" signal, the second marks churn
rather than remediation.

### Triage drop-downs

* Applicable at [ORG]? — Yes / No - technology or pattern not used here / No - risk accepted by architecture / Partially - needs Project/BI scoping / Undetermined
* Premise Holds Here? — Yes / Partially / No
* Inputs Accurate? — Yes / CCR finding inaccurate / Exposure analysis inaccurate / Permission (CIEM) over-report / Vulnerability data stale / Scan coverage gap / Mixed / Not reviewed
* Primary FP Cause — None / Input finding wrong (CCR) / Exposure calculation wrong / CIEM over-report / Sanctioned pattern not modelled / Stale or deleted entity / Scan coverage gap / Control logic too broad / Duplicate of another control / Other
* Disposition — Keep as-is / Keep - scope by Project or Business Impact / Keep - Ignore Rule for sanctioned pattern / Tune input rule (CCR) / Clone and refine query / Disable Issue generation only / Disable control / Escalate to Wiz support / Severity override (last resort) / Undetermined
* Governance Outcome — A–F from SEC-STD-WIZ-001 plus "Rule validated - no change"

## Schema notes (verify on first live run)

* `controls` node fields come from Wiz's own Postman collection (`ManageControlsTable`): `id name description type severity query enabled lastRunAt lastSuccessfulRunAt lastRunError scopeProject sourceCloudConfigurationRule securitySubCategories enabledForLBI/MBI/HBI/Unattributed createdBy issueAnalytics(selection:){issueCount}`. `scopeQuery risks tags createdAt updatedAt supportsNRT hasAutoRemediation resolutionRecommendation` are LIKELY and pruned automatically if absent.
* `issueAnalytics` takes `ControlIssueAnalyticsSelection`; the script introspects its input fields and passes `{status: [OPEN, IN_PROGRESS]}` when a status field exists, otherwise `{}`. The selection used is recorded on Summary.
* `Issue.notes` is not selected (removed 2026-11-16). `entitySnapshot.cloudProviderURL`/`tags` are pruned if absent.
* `controls` is a non-WIN root with no schema-stability guarantee; the script introspects and prunes on `GRAPHQL_VALIDATION_FAILED`, logging every pruned field.
* Deep links use the documented formats `/issues#~(issue~'<id>)` and `/issues#~(entity~(~'<id>*2c<TYPE>))`; set `--app-url` for non-commercial consoles.

## Exit codes

0 success · 2 partial (CCR resolution forbidden or skipped by error) · 1 fatal (auth, DC, scopes, network).

## Testing

```bash
python3 tests_mock_wiz_gc.py 8766 &                       # or --no-introspection / --forbid-ccr
export WIZ_CLIENT_ID=mock WIZ_CLIENT_SECRET=mock \
       WIZ_AUTH_URL=http://127.0.0.1:8766/oauth/token WIZ_API_URL=http://127.0.0.1:8766/graphql
python3 wiz_graph_control_triage.py --pause 0 --org "S&P" -o mock.xlsx
```

The mock covers: JWT `dc` claim, introspection on/off, fields missing from the tenant schema,
`issueAnalytics(selection:)`, a 429 with `Retry-After`, FORBIDDEN on CCRs, an Issue whose control no
longer exists (synthetic row), a config-rule-as-control, a control with an unparseable query.
