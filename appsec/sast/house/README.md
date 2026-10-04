# House SAST rules

Rules written for CISO Toolbox, in the Semgrep/Opengrep rule format, run by
AppSec next to the security rules of the opengrep-rules snapshot.

- One file per topic, under a directory named after the language
  (`python/`, `javascript/`, `generic/`…), each rule with a `metadata`
  block (`category`, `cwe`, `confidence`, `likelihood`, `references`).
- A rule is reported as `house.<dirs>.<file>.<rule id>`.
- The image build validates every rule (`opengrep scan --validate`): a
  malformed rule fails the build, not a scan.
