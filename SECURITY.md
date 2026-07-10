# Security policy

## Scope

This repository is a device-specific research proof of concept. Reports about
unexpected behavior on the explicitly supported firmware profile, unsafe
failure handling, incomplete kernel-state restoration, or accidental exposure
of sensitive data are in scope.

Requests to adapt the exploit to unrelated devices, deploy it without the
owner's authorization, bypass the supported-profile checks, or add persistence
are out of scope.

## Reporting

Use a private security-reporting channel provided by the repository host. If no
private channel is configured, contact the maintainers privately before opening
a public issue.

Include the smallest reproduction needed and redact device serial numbers,
account details, private firmware, memory dumps, and unique identifiers. Do not
attach full `results/` directories to public issues.

## Operational safety

Testing may panic or reboot the target. Use only owned or explicitly authorized
hardware, keep a recovery path available, and start with `--preflight-only` and
`--validate-only` before running the complete chain.
