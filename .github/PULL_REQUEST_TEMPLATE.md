## What & why

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `npm run build && npm test` passes locally
- [ ] New behavior has tests (detection rules: true-positive **and** false-positive cases)
- [ ] README/docs updated if user-facing
- [ ] No `console.log` in gateway code paths (stdout carries the protocol — use `log.*`, it goes to stderr)
