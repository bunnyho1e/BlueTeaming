#!/usr/bin/env python3
"""Render the human-readable catalog from the reviewed, pinned source records."""
from collections import Counter
import json
import html
from pathlib import Path
import re
from fetch_sources import validate_catalog

ROOT = Path(__file__).resolve().parent


def cell(value):
    text = html.escape(str(value or ''), quote=False).replace('|', '&#124;').replace('\n', ' ').strip()
    return text.replace('\\', '\\\\').replace('[', '\\[').replace(']', '\\]').replace('`', '\\`')


def project(row):
    return '[' + cell(row['slug']) + '](' + row['url'] + ')'


def pin(row):
    return '[' + row['commit'][:12] + '](' + row['pin_url'] + ')'


def write(name, lines):
    (ROOT / name).write_text('\n'.join(lines).rstrip() + '\n', encoding='utf-8')


def main():
    data = json.loads((ROOT / 'catalog.json').read_text())
    review = json.loads((ROOT / 'source-review.json').read_text())
    excluded = json.loads((ROOT / 'excluded.json').read_text())
    rows = validate_catalog(data)
    by_id = {r['id']: r for r in rows}
    hosts = Counter(r['host'] for r in rows)
    types = Counter(r['source_type'] for r in rows)
    modes = Counter(r['inspection_mode'] for r in review['repositories'])
    total = len(rows)
    date = data['review_date']
    category_counts = Counter(r['category'] for r in rows)
    profile_purposes = {
        'starter': 'A compact first selection for detection, triage and source exploration.',
        'soc': 'Security platforms, endpoint visibility, detection content and telemetry.',
        'incident-response': 'Evidence collection, timelines and investigation support.',
        'dfir': 'Windows, memory, disk, mobile and macOS artifact analysis.',
        'detection': 'Sigma, analytics, event-log triage and ATT&CK content.',
        'network': 'Network telemetry, IDS, packet analysis and deception.',
        'threat-intelligence': 'Enrichment, sharing, indicator management and intelligence.',
        'cloud': 'Cloud posture, identity investigation and cloud incident response.',
        'containers': 'Kubernetes, runtime monitoring, policy and image assessment.',
        'hardening': 'Host auditing, compliance content and defensive configuration.',
        'supply-chain': 'Secrets, source analysis, SBOMs and artifact verification.',
        'identity': 'Identity posture, access control, certificates and secrets.',
        'email': 'Mail filtering, DMARC and phishing investigation.',
        'malware-lab': 'Malware triage and reverse engineering; use an isolated lab.',
        'validation-lab': 'Adversary simulation and test content; use an isolated lab.',
    }
    banner = '''<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="270" viewBox="0 0 1200 270" role="img" aria-labelledby="title desc">
<title id="title">BlueTeaming</title><desc id="desc">Defensive security sources with transparent review evidence.</desc>
<defs><linearGradient id="bg" x2="1" y2="1"><stop stop-color="#071322"/><stop offset="1" stop-color="#102b48"/></linearGradient><linearGradient id="accent" x2="1" y2="1"><stop stop-color="#57e1ed"/><stop offset="1" stop-color="#4286ff"/></linearGradient></defs>
<rect width="1200" height="270" rx="18" fill="url(#bg)"/>
<g fill="none" stroke="#296395" stroke-opacity=".22"><path d="M800 0v270M880 0v270M960 0v270M1040 0v270M1120 0v270M760 55h440M760 135h440M760 215h440"/><circle cx="1000" cy="135" r="104"/><circle cx="1000" cy="135" r="66"/></g>
<g transform="translate(65 55)"><path d="M64 0 124 24v51c0 43-28 69-60 86C32 144 4 118 4 75V24Z" fill="#0d3152" stroke="url(#accent)" stroke-width="4"/><path d="M30 81h22l12-29 18 54 12-25h18" fill="none" stroke="url(#accent)" stroke-width="7" stroke-linecap="round" stroke-linejoin="round"/></g>
<g font-family="Inter,Segoe UI,Arial,sans-serif"><text x="238" y="92" font-size="16" font-weight="600" letter-spacing="3" fill="#72dbe9">DETECTION / RESPONSE / DEFENSE</text><text x="235" y="155" font-size="58" font-weight="750" fill="#f4f8ff">BlueTeaming</text><text x="238" y="193" font-size="20" fill="#b6cce2">Practical capabilities. Transparent evidence.</text><text x="238" y="233" font-size="15" fill="#89b2d7">COUNTS</text></g>
</svg>'''.replace('COUNTS', f'{total} source projects   /   {len(data["categories"])} capability areas   /   {len(data["profiles"])} workflow profiles')
    (ROOT / 'banner.svg').write_text(banner + '\n', encoding='utf-8')
    lines = ['![BlueTeaming](banner.svg)', '', '# BlueTeaming', '',
      '**See clearly. Investigate precisely. Defend with evidence.**', '',
      'A curated workspace of defensive security tools, platforms, libraries, detection content and integrations from canonical GitHub and GitLab sources.', '',
      f'**{total} active source projects · {hosts["github"]} GitHub · {hosts["gitlab"]} GitLab · {len(data["categories"])} categories · {len(data["profiles"])} workflow profiles**', '',
      f'Initial source screen: **{date}**. Every active entry has an exact commit pin, dated review evidence, an inspection scope and a usage class. Counts refer to distinct source projects, not installed products or command aliases.', '',
      '[Browse the catalog](CATALOG.md) · [Choose a workflow](WORKFLOWS.md) · [Review evidence and limits](SOURCE_REVIEW.md) · [Excluded candidates](EXCLUDED.md)', '',
      '## Start with the sources', '',
      'Requirements: Git and Python 3.9 or newer. The helper has no third-party Python dependencies.', '',
      '```bash', 'git clone https://github.com/bunnyho1e/BlueTeaming.git', 'cd BlueTeaming',
      'python3 fetch_sources.py --profile starter --dry-run',
      'python3 fetch_sources.py --profile starter --jobs 4', '```', '',
      'A normal clone retrieves this catalog and its helpers. The next step fetches upstream source into `tools/<category>/<host>/<project>/` at the recorded commits. It does not install packages, execute tools, build containers, initialize nested submodules or retrieve Git LFS payloads. Build and deployment instructions remain with each upstream project.', '',
      '```bash', 'python3 fetch_sources.py --profile incident-response --dry-run',
      'python3 fetch_sources.py --profile detection --jobs 4',
      'python3 fetch_sources.py --category network-defense --dry-run',
      'python3 fetch_sources.py --repo github:SigmaHQ/sigma --dry-run',
      'python3 fetch_sources.py --all --dry-run', '```', '',
      '`--all` includes specialized analysis and lab source projects. Select a workflow or individual source before retrieving the complete collection. No deployment, agent registration or target-facing operation is performed by the helper.', '',
      '## Workflow profiles', '', '| Profile | Sources | Intended use |', '| --- | ---: | --- |']
    for name, ids in data['profiles'].items():
        lines.append(f'| `{name}` | {len(ids)} | {profile_purposes[name]} |')
    lines += ['', '## Capability map', '', '| Area | Sources |', '| --- | ---: |']
    for category in data['categories']:
        lines.append(f'| [{category["title"]}](CATALOG.md#{category["id"]}) | {category_counts[category["id"]]} |')
    lines += ['', '## What the screen establishes', '',
      'The selection checks canonical provider identities, archive/fork/activity metadata, exact commits, bounded source text, selected build and entrypoint files, and known-advisory query results. Suspicious-pattern matches are retained with context. Detection rules often mention malicious behavior because detecting it is their purpose.', '',
      f'The active set contains **{modes["BOUNDED_SNAPSHOT"]} bounded snapshot screens** and **{modes["SELECTED_FILES_ONLY"]} selected-file inspections**. Neither is a full code audit or a malware-free certificate. Dependencies, downloaded payloads, release binaries, container images, nested repositories and runtime behavior are outside this review.', '',
      'Archived, stale, unresolved, insufficiently inspected and advisory-matching candidates remain outside every active download profile. An exclusion is a selection decision, not an accusation of malware. Provider stars are a discovery signal, never a security guarantee.', '',
      'The helper validates the same allowlist for every selection. It rejects noncanonical URLs, invalid pins, path traversal, destination symlinks, external Git directories and unreviewed local Git settings. Hooks, filesystem monitors, inherited Git overrides and automatic submodule recursion are disabled for retrieval.', '',
      '## Repository guide', '', '| File | Purpose |', '| --- | --- |',
      '| [CATALOG.md](CATALOG.md) | Every active source, purpose, type, license, usage class and exact pin. |',
      '| [WORKFLOWS.md](WORKFLOWS.md) | Practical selection paths for analysts and platform engineers. |',
      '| [SOURCE_REVIEW.md](SOURCE_REVIEW.md) | Method, evidence scope and project-level review table. |',
      '| [source-review.json](source-review.json) | Dated observations, fingerprints, indicators and advisory results. |',
      '| [catalog.json](catalog.json) | Active source allowlist and workflow profiles. |',
      '| [EXCLUDED.md](EXCLUDED.md) | Held candidates and the reasons. |',
      '| [THIRD_PARTY.md](THIRD_PARTY.md) | Upstream ownership and license observations. |',
      '| [SECURITY.md](SECURITY.md) | Reporting policy and operational review boundary. |',
      '| [CONTRIBUTING.md](CONTRIBUTING.md) | Addition and pin-update requirements. |', '',
      '[Validation record](VALIDATION.md) · [Automated validation](https://github.com/bunnyho1e/BlueTeaming/actions/workflows/validate.yml)', '',
      '## Validate and maintain', '', '```bash', 'python3 -m unittest -v',
      'python3 render_catalog.py', 'python3 fetch_sources.py --all --dry-run',
      'python3 review_sources.py --repo github:SigmaHQ/sigma', '```', '',
      'The review helper writes observations to `audit-output/`; it does not approve or update catalog pins automatically. Revisit upstream advisories before building or deploying a pinned development snapshot. See [CONTRIBUTING.md](CONTRIBUTING.md) for the review bar.', '',
      '## License', '', 'Original catalog text and helper code: [MIT](LICENSE). Every upstream project retains its own license, ownership and trademarks. A catalog entry does not relicense upstream source or grant rights beyond its published terms.']
    write('README.md', lines)

    lines = ['# Source catalog', '', f'**{total} distinct active source projects, screened on {date}.**', '',
      '[Workflow guide](WORKFLOWS.md) · [Review method](SOURCE_REVIEW.md) · [Machine-readable catalog](catalog.json)', '',
      'Projects are grouped by their primary operational role and may support several workflows. Tools, platforms, libraries, content and integrations are labeled separately. Stars and licenses are dated provider observations. An exact source commit can be a development snapshot rather than a supported production release.', '',
      '| Source type | Count |', '| --- | ---: |']
    for name, count in sorted(types.items()):lines.append(f'| {name} | {count} |')
    lines += ['', 'Usage classes describe deployment considerations; they do not authorize execution. `ISOLATED_LAB` covers adversary simulation and test content. `MALWARE_ANALYSIS_ISOLATED` covers tools intended to inspect hostile files. Other classes identify privileged evidence collection, sensitive data, system changes or source-only content.', '']
    for category in data['categories']:
        lines += ['## ' + category['title'], '', category['description'], '',
                  '| Project | Purpose | Type | Host / stars | License | Usage class | Exact source |',
                  '| --- | --- | --- | --- | --- | --- | --- |']
        for row in sorted((r for r in rows if r['category']==category['id']),key=lambda r:(-(r.get('stars') or 0),r['id'].lower())):
            lines.append('| ' + ' | '.join([project(row),cell(row['purpose']),row['source_type'],
              row['host']+' / '+str(row.get('stars') if row.get('stars') is not None else 'unknown'),
              cell(row['license']),row['usage_class'],pin(row)]) + ' |')
        lines.append('')
    write('CATALOG.md', lines)

    lines = ['# Source screening and evidence', '', f'**Review date: {date}. Active projects: {total}.**', '',
      '[Full evidence](source-review.json) · [Held candidates](EXCLUDED.md) · [Security policy](SECURITY.md)', '',
      '## Method and boundaries', '',
      '1. Resolve the canonical GitHub or GitLab project, record provider metadata, deduplicate aliases and prefer original upstreams over forks.',
      '2. Hold archived or disabled projects and sources without provider-reported activity in the previous three years. Activity and popularity are quality signals, not security attestations.',
      '3. Resolve a complete 40-character commit and retain its provider date. Provider-reported signature status is recorded when available; this workflow does not independently verify maintainer signing keys.',
      '4. Query OSV for the exact commit. A matching advisory places that candidate on hold. No match can mean no indexed record; it does not establish the absence of vulnerabilities.',
      '5. Read a bounded source snapshot or selected pinned files without extracting or executing upstream code. Fingerprint inspected bytes with SHA-256. Selected GitHub files are checked against tree blob hashes where available.',
      '6. Examine indicators for remote installer pipelines, encoded execution, credential-store references, webhooks, miners, persistence and changes to security controls. Retain contextual interpretations and appropriate usage classes.', '',
      'The snapshot path limits compressed input to 24 MiB, expanded regular-file bytes to 128 MiB, individual files to 1 MiB and archive members to 90,000. It scans selected common source/config/rule suffixes and build manifests. Non-text files, large files, symlinks and unselected suffixes are omitted. Source archives may apply upstream export attributes. A snapshot fingerprint records retrieved bytes, not a signed publisher attestation.', '',
      'Large source trees and bounded-download failures use selected-file inspection. A selected-file screen requires at least three inspected text files, including a source/config/build file. A complete bounded snapshot of a small project can pass with two text files when one contains source or configuration. These are minimum evidence gates, not comprehensive assurance. Limits and errors remain attached to each record. The private working set retains selected source text; the published evidence contains its paths, hashes and representative indicator excerpts.', '',
      'Where direct GitLab source downloads were unavailable, matching commit objects in the upstream GitHub mirrors were used for Wireshark, AppArmor and GnuTLS. Their canonical origins remain GitLab. The cross-provider commit check, retrieval URLs and byte fingerprints are recorded explicitly. Provider UTF-8 decoding limits and omitted symlink entries are recorded rather than treated as malware findings.', '',
      'No upstream installer, agent, exploit, module or container was run. No live malware was detonated and no protected environment was scanned. The collection is not a full dependency, binary, runtime or maliciousness audit.', '',
      '## Scope totals', '', '| Mode | Active sources |', '| --- | ---: |']
    for mode,count in sorted(modes.items()):lines.append(f'| `{mode}` | {count} |')
    lines += ['', f'Text files screened: **{sum(r["scanned_text_files"] for r in review["repositories"]):,}**. Text bytes screened: **{sum(r["scanned_text_bytes"] for r in review["repositories"]):,}**. These are automated screen counts, not counts of manually audited files.', '',
      '## Contextual review', '']
    lines += review['contextual_review_notes'] + ['', '## Active project observations', '',
      '| Source | Inspection mode | Text files | Advisory result | Exact pin |', '| --- | --- | ---: | --- | --- |']
    for record in sorted(review['repositories'],key=lambda r:r['id'].lower()):
        row=by_id[record['id']]
        advisory='No indexed record returned' if record['osv']['status']=='NO_RECORD_RETURNED' else record['osv']['status']
        lines.append('| '+' | '.join([project(row),record['inspection_mode'],str(record['scanned_text_files']),advisory,pin(row)])+' |')
    write('SOURCE_REVIEW.md',lines)

    lines=['# Held and excluded candidates','',
      'These identities are outside the active catalog and every workflow profile. Exclusion covers quality, scope, provenance, inspection or advisory concerns; it does not by itself establish maliciousness.', '',
      '[Machine-readable decisions](excluded.json) · [Review method](SOURCE_REVIEW.md)', '',
      '| Candidate identity | Decision | Reason |', '| --- | --- | --- |']
    for record in sorted(excluded['candidates'],key=lambda r:r['id'].lower()):
        lines.append('| `' + cell(record['id']) + '` | `' + record['decision'] + '` | ' + cell(record['reason']) + ' |')
    write('EXCLUDED.md',lines)

    lines=['# Upstream attribution and licenses','',
      'All upstream code remains owned by its original authors and is fetched from its original provider. No upstream source tree, binary distribution or license is copied into this repository. Provider license detection can be incomplete; inspect the exact upstream license and file notices before redistribution or deployment.', '',
      '| Original source | Provider license observation | Fixed source |', '| --- | --- | --- |']
    for row in sorted(rows,key=lambda r:r['id'].lower()):lines.append('| '+' | '.join([project(row),cell(row['license']),pin(row)])+' |')
    write('THIRD_PARTY.md',lines)
    print(f'Rendered {total} active sources, {len(data["categories"])} categories and {len(data["profiles"])} profiles.')


if __name__=='__main__':main()
