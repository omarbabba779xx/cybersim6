## Summary

- Describe the main change in 1-3 bullet points

## Why

- Explain the problem solved or the value added

## Scope

- Modules affected:
- Docs updated:
- Tests added/updated:

## Validation

- [ ] `python -m pytest tests -q`
- [ ] `python -m flake8 cybersim --max-line-length=120 --extend-ignore=E501,W503,E203`
- [ ] `python -m bandit -r cybersim -ll -q`

## Safety Checklist

- [ ] Targets remain localhost / loopback only
- [ ] Sandbox protections remain intact
- [ ] No real credentials, emails, or production targets are used
- [ ] Security-sensitive behavior is documented

## Screenshots / Notes

- Add screenshots or extra reviewer notes if relevant
