# Blue team workflows

Choose a capability and the smallest useful source set. A workflow profile is
a curated source selection, not a turnkey deployment. Consult each project's
supported release, operating system, prerequisites and upstream documentation.

## SOC foundation

Start with `starter` to explore detection content and analysis helpers. Use
`soc` when evaluating a wider stack. Compare a platform's event schema, retention,
access controls, deployment cost and integration needs before choosing it.

| Need | Starting points | Operational consideration |
| --- | --- | --- |
| Host visibility | osquery, Fleet, Wazuh | Scope collection, access and retention before enrolling endpoints. |
| Network evidence | Zeek, Suricata, Arkime, Wireshark | Sensor placement, capture permissions and privacy determine useful visibility. |
| Detections | Sigma, Elastic detection rules, Splunk security content | Translate for the target backend and tune against representative logs. |
| Case handling | DFIR-IRIS, Cortex, Timesketch | Treat evidence, integrations and case access as sensitive data. |
| Intelligence | MISP, OpenCTI, IntelOwl | Validate sharing restrictions, enrichment destinations and API credentials. |

```bash
python3 fetch_sources.py --profile starter --dry-run
python3 fetch_sources.py --profile soc --jobs 4
```

Only active catalog members are fetched; held candidates are recorded separately.

## Detection engineering

Use `detection` for rules, translation libraries, event-log triage and ATT&CK
content. Confirm that required telemetry is collected before measuring coverage.
Tune false positives using representative benign activity and version rules in
the same change process as the systems that consume them.

Sigma rules, Hayabusa, Chainsaw and backend-native analytics serve different
roles. A rule's ATT&CK mapping is a claim about behavior coverage, not evidence
that a control has been tested successfully in your environment.

## Incident response and DFIR

Use `incident-response` for collection and timelines, or `dfir` for broader
artifact analysis. Preserve original evidence, record collection times and tool
versions, and work on copies when possible. Memory, browser, registry and cloud
artifacts may contain credentials and personal information.

| Evidence | Useful source families |
| --- | --- |
| Endpoint collection | Velociraptor, Acquire, GRR, DFIR ORC |
| Timelines and correlation | Plaso, Timesketch, Dissect |
| Windows artifacts | Eric Zimmerman tools, EVTX parsers, RegRipper |
| Memory | Volatility 3, MemProcFS, WinPmem |
| Mobile and macOS | ALEAPP, iLEAPP, mac_apt, UnifiedLogReader |
| Cloud and M365 | Untitled Goose Tool, HAWK, Microsoft Extractor Suite, cloud-forensics-utils |

An upstream listed here may be held in the initial review. The active catalog
and profile dry run are authoritative for what this collection will retrieve.

## Cloud, identity and container defense

Use `cloud`, `identity` or `containers`. Separate assessment credentials from
remediation credentials, choose the least privilege that supports the task and
test policies before enabling enforcement. A source download configures no cloud
account, identity provider, admission controller or production workload.

Cloud posture tools, audit-log collectors and runtime sensors solve different
problems. Prowler, ScoutSuite and Cloud Custodian do not replace Kubernetes
policy engines, endpoint telemetry or an incident collection plan.

## Hardening and vulnerability management

Use `hardening`, `supply-chain`, or the `vulnerability-management` category.
Review proposed configuration changes, maintenance windows and recovery paths
before applying a baseline. Use an asset inventory and supported upstream
release advisories to prioritize vulnerabilities.

Secrets detection tools can validate discovered credentials with remote services.
Review upstream options before running them on sensitive repositories. A current
source snapshot can still have dependency or deployment vulnerabilities.

## Malware analysis and defensive validation

Use `malware-lab` for analysis sources and `validation-lab` for deliberate
adversary simulation. Both are explicitly outside the starter profile. Run these
workflows in a controlled lab with suitable network boundaries and disposable
systems. The source fetcher never opens suspicious documents, loads memory dumps,
detonates samples or runs simulation procedures.

Do not point a honeypot at production secrets or route captured credentials to
unreviewed destinations. Reverse engineering and emulation tooling can process
hostile input; protect the analysis environment itself.

## Keep the collection current

Review exact source pins, upstream advisories and build dependencies before
deployment. Re-screen proposed upgrades and inspect the changed code; do not
replace commit pins with moving branch references. See CONTRIBUTING.md for the
addition requirements and SOURCE_REVIEW.md for the initial review's limits.
