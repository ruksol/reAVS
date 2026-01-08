# Test Suite Strategy

This test suite is designed for end-to-end and system-level validation of AVS.

Coverage philosophy:
- Prefer black-box and gray-box checks that validate observable behavior.
- Exercise scanners through full ScanContext runs using lightweight fake APK/DEX objects.
- Validate IR extraction, taint flow, rule detection, and reporting with deterministic fixtures.
- Use golden files for JSON reports to lock schema and output stability.
- Keep tests deterministic and fast; avoid network or external build steps.

Layout:
- pipeline/: APK loading, manifest parsing, and scan setup behavior.
- ir/: IR extraction, taint tracking, and stability checks.
- rules/: Positive, negative, and edge-case tests for each rule.
- reporting/: JSON schema (golden files).
- cli/: CLI output behavior and verbosity handling.
- regression/: Stress and regression checks for stability and performance sanity.
