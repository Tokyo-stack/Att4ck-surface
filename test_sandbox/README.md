# ATT4ck Surface — Test Sandbox

Deliberately vulnerable **and** correctly-sanitized code samples covering all
40 attack surfaces. **None of this code is meant to run** — it exists so the
scanner's detectors and sanitization-awareness can be exercised end to end.

Layout:

```
test_sandbox/
  vulnerable/<surface>/...   # each file MUST trigger its surface's rule (VULNERABLE)
  sanitized/<surface>/...    # the mitigated counterpart (no finding, or POTENTIALLY_MITIGATED)
```

The integration test (`tests/test_integration.py`) scans this tree and asserts
that every surface fires in `vulnerable/` and that the `sanitized/` counterparts
are clean or explicitly marked as potentially mitigated.

> ⚠️ Do not deploy or import these files. Secrets here are fake, high-entropy
> placeholders used purely to exercise detection.
