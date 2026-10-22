# Contributing

Contribute a defensive capability with a clear operational use case. Prefer a
maintained upstream project over forks, binary bundles and duplicate wrappers.

An addition or pin update must include:

1. Canonical GitHub or GitLab HTTPS identity and a full 40-character commit SHA.
2. Primary category, concise purpose, appropriate usage class and upstream license.
3. Provider archive/fork/activity observations and the date checked.
4. Reproducible inspection scope, source fingerprints, relevant indicator context
   and the result of a known-advisory query for that exact pin.
5. A reasoned inclusion decision. Unknown, unreachable or incomplete checks stay
   outside active profiles until resolved.

Keep tools, libraries, rules, datasets and platforms labeled accurately. Do not
inflate tool counts by repeating command names, mirrors or aliases. A missing
license is not an open-source license. Do not copy upstream binaries or malware
samples into this repository.

Update catalog.json and source-review.json together, then run:

```bash
python3 -m unittest -v
python3 render_catalog.py
python3 fetch_sources.py --all --dry-run
```

Review generated Markdown and the changed pin diff. Source checks are not a
malware-free certificate; describe exactly what the evidence supports.
