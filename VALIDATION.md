# Validation record

Initial review date: **2026-10-21**. Runtime used for local checks: Python 3.12
with Git on Linux. The helper source also passes Python 3.9 grammar validation;
the full test suite was not run under Python 3.9 in this environment.

| Check | Result |
| --- | --- |
| Catalog and retrieval safety tests | 14 tests passed. |
| Workflow selection | All 15 profiles validated. |
| Category selection | All 20 categories validated. |
| Complete dry run | Exactly 410 distinct active source projects selected. |
| Review-to-catalog correspondence | Every active identity and commit matches the published evidence. |
| Exclusion enforcement | Held identities are outside all active profiles. |
| Markdown generation | Re-running the renderer produces identical output. |
| Local documentation links | Referenced repository files exist. |
| Source inspection | 189 bounded snapshots and 221 selected-file inspections. |
| Known-advisory queries | 427 exact source-commit queries recorded across the review batches. |
| Live source retrieval | Three successful exact-pin fetches across GitHub and GitLab. |

Live retrieval checks used `SigmaHQ/sigma-cli`, `williballenthin/python-evtx` and
the canonical GitLab `apparmor/apparmor` repository. Git checked out the expected
commit in each case; no upstream code was executed. Exact checked pins are in
[validation-results.json](validation-results.json).

Tests cover altered pins and URLs, path traversal, duplicate and held identities,
outdated/missing review evidence, symlink destinations, external Git directories,
nonempty destinations, dangerous local Git settings, inherited Git overrides and
origin mismatches. These checks do not execute or install upstream tools.

The GitHub workflow validates the exact event commit using Git and the runner's
Python. It uses no third-party GitHub Actions, package installers or network
retrieval of upstream catalog members. Its only repository permission is
`contents: read`. See the Actions page for actual hosted-run status; local
results do not imply that hosted CI has already completed.

Source byte inspection and provider identity checks are separate from deployment
testing. No claim is made that all source projects build, run, integrate together,
support every operating system or are free of malicious behavior. See
SOURCE_REVIEW.md for the scope and omitted dependencies/artifacts.
