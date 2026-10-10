# Security policy

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability
reporting on this repository (Security tab, "Report a vulnerability"). Please
do not open a public issue.

- Reports are acknowledged within 5 working days.
- A disclosure date is agreed with the reporter: by default 90 days after the
  report, or earlier once a fix is released.
- Fixes ship as a new version with a GitHub security advisory that names the
  affected versions and credits the reporter, unless they ask otherwise.

## Supported versions

The latest release and the `main` branch receive fixes.

## Scope

The qrtc source in this repository, including the patched crates under
`vendor/`, its build and test configuration, and its published releases.
Issues in upstream str0m or dimpl that also affect the vendored copies are
welcome here and will be forwarded upstream.

## More

- [COMPLIANCE.md](COMPLIANCE.md): the cybersecurity policy and CrabNebula's
  status as an open-source software steward under the Cyber Resilience Act.
- [audits/](audits/): security reviews and their findings.
- [deny.toml](deny.toml): advisories judged not to affect qrtc, with reasons.
