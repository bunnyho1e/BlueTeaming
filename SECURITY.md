# Security policy

This repository distributes a catalog, exact source references, review evidence
and a source retrieval helper. It does not install or execute upstream tools.

## Reporting a concern

For a vulnerable upstream project, use that project's own SECURITY policy or
maintainer reporting channel. For a suspicious catalog entry, wrong source
identity, compromised pin or helper issue, open a GitHub issue with the source
ID, commit, affected file and reproduction details that are safe to disclose.
Do not post credentials, customer evidence, live malware or confidential logs.
Use GitHub private vulnerability reporting if it is enabled on this repository;
otherwise agree on a private channel with the maintainer before disclosing secrets.

## Review boundary

Every active entry has dated source provenance and static screening evidence.
Automated text indicators are investigation leads, not malware verdicts. No
pattern match is not proof of safety. Large projects receive selected-file
inspection; transitive dependencies, release executables, container images,
submodules and runtime behavior require separate review. The exact inspection
mode and omitted scope are recorded in source-review.json.

Changes to source identities or pins require a fresh review. A previously checked
pin does not approve a newer release. Validate the deployment version against
current upstream advisories and your environment's change controls.

## Handling sensitive capabilities

Collection agents and memory tools can access privileged evidence and secrets.
Identity, cloud, case management and automation platforms can expose sensitive
data or change systems. Malware analysis tools, honeypots and adversary validation
sources require appropriate isolation. Use the usage classes and workflow guide
to choose the smallest useful source set. Fetching sources is a separate step
from building, installing or running them.
