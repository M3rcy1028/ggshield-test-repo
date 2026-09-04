# ggshield-test-repo

A small Python security-event analyzer used to test GitGuardian `ggshield` scanning and Git hooks.

## Run

```powershell
python .\ggshield-test.py
python .\ggshield-test.py --json
```

The built-in demo data contains repeated failed login events so the program can demonstrate alert reporting without external dependencies.

## Documentation

- [ggshield pre-commit 차단 테스트 보고서](GGSHIELD_TEST_REPORT.md)
