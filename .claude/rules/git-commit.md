## Git Commit Rules

This project follows [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

### Title Format

<type>(<scope>): <subject>

- type:    feat | fix | docs | style | refactor | perf | test | chore
- scope:   optional (e.g. auth, setup, main)
- subject: required, imperative mood (`add`, `fix`, `update` — not `added`, `fixed`, `updated`)
- Keep the title under 72 characters.

### Body (optional but recommended)

Add a blank line after the title, then explain:
- What: what changed and what it does
- Why: the reason for this change

### Footer

Add a blank line after the body (or title if no body), then reference the issue:

Fixes: #<number>

### Rules

- One commit = one purpose. Split unrelated changes into separate commits.
- Write the body when the change is non-trivial.

### Examples

feat(auth): add OAuth2 support

What: Adds OAuth2 login flow using the Google provider.
Why: Security audit flagged password login as insufficient.

Fixes: #123

---

fix: correct null response

Fixes: #42
