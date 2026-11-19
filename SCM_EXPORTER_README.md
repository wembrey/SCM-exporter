# SCM exporter v1.4

The exporter now creates **one multi-tab Excel workbook per run**. Temporary JSON and CSV data are removed after the workbook is produced.

## Run

```bash
py scm_exporter.py --auto-export --output ./scm-export
```

Output:

```text
scm-export/SCM_Evidence_YYYYMMDDTHHMMSSZ.xlsx
```

## Workbook tabs

- **Summary**: TSG, timestamp, query counts, record counts and selected-scope counts.
- **Tenant Scopes**: discovered folders, snippets and devices, including whether each was selected.
- **API Results**: every API request with scope, status, HTTP status, record count and diagnostic error.
- **One tab per resource type**: addresses, services, security rules, zones, interfaces, routing, VPN, profiles and device settings. Each resource tab combines all selected scopes and includes `_scope_type` and `_scope_name` columns.

Successful zero-result queries stay in **API Results**, even though their resource tab is empty. This preserves evidence that SCM returned no matching configuration.

## Resilience

The automatic evidence set excludes large reference-data endpoints such as the full applications catalogue. Each SCM GET has a 20-second default timeout and a 100 ms delay between calls.

```bash
py scm_exporter.py --auto-export --request-timeout 30 --delay 0.25 --output ./scm-export
```

## Scope filtering

```bash
py scm_exporter.py --auto-export \
  --scope-type folder \
  --scope-regex '^Lab Firewalls$' \
  --output ./scm-export
```

Use `--include-system-scopes` only when predefined/default snippets are required.

## v1.5 HA and optional endpoint selection

HA is now included in the default evidence set using the documented SCM NGFW endpoints:

- `ha-devices` -> `/config/device/v1/ha-devices`
- `ha-configurations` -> `/config/device/v1/ha-configurations`

The workbook also contains an **Excluded Options** sheet listing endpoints deliberately pruned from the default collection, the reason, and whether they were included in that run.

From the command line:

```bash
py scm_exporter.py --list-pruned
```

For an interactive run:

```bash
py scm_exporter.py --auto-export --menu --output ./scm-export
```

The menu shows optional/pruned endpoint groups and lets you opt them back in for that export. Press Enter to keep the normal LLD-focused defaults.

You can still bypass the menu and explicitly request optional endpoints using repeated `--endpoint` arguments.
