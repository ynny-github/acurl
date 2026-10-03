---
name: create-pr
description: Use when asked to create, open, or submit a pull request on GitHub. Guides pre-collection, self-assessment, template filling, and PR submission via GitHub MCP or gh CLI.
---

# Create PR

## When to Use

Use this skill whenever asked to create, open, or submit a pull request.

## Workflow

### Step 1: Pre-collection

Gather context before writing anything.

Run:
```bash
git diff main...HEAD --stat
git log main...HEAD --oneline
```

Identify the linked issue number from the branch name, recent commits, or conversation context.

While gathering context, also collect candidate links for the **`[AI] Context`** section from:

1. **Conversation / user statements** — PR URLs, issue URLs, or reference links the user mentioned or pasted during the session.
2. **Commits and code** — links inside commit messages, diff hunks, and code comments / docstrings touched by this change.
3. **AI-judged references** — well-known docs (RFCs, language refs, library docs) that materially helped justify the change.

Do **not** run external lookups (`gh search`, MCP search, web fetch) for this — sources are limited to what is already visible to the agent. Defer the keep/drop decision to Step 3.

### Step 2: Self-assessment

Before filling the template, answer these questions internally:

1. Which decisions did I make that I am uncertain about?
2. What alternatives did I consider and why did I not use them?
3. What tests exist that cover this change?
4. What did I actually run or verify during implementation?

These answers become the content of **AI Confidence Notes** and **AI Verification Done**.

### Step 3: Fill the template

Fill every `[AI]` section in the AI PR template at `.claude/skills/create-pr/pull_request_template.md`. No required section may be left blank or skipped. The optional `[AI] Context` subsections follow the Deletion rules below.

This skill's template — not `.github/pull_request_template.md` — is the source of truth for AI-authored PRs. The repo's `.github/pull_request_template.md` is reserved for human-authored PRs and must not be used here.

| Section | What to write |
|---|---|
| **Closes** | Replace `#<issue number>` with the actual GitHub issue number (e.g., `Closes: #42`) identified in Step 1 |
| **Summary** | One paragraph describing what this PR does |
| **What Changed** | What was changed and why |
| **Impact Scope** | Which components/APIs/users are affected and how significantly |
| **Implementation Decision** | Key decisions and why this approach was chosen over alternatives |
| **Test Coverage** | What tests cover the purpose of this PR |
| **AI Verification Done** | What was actually run (build, tests, flash, manual check, etc.) |
| **AI Confidence Notes** | Uncertainties or decisions needing human judgment. Write "No significant uncertainties." if fully confident. |
| **[AI] Related PRs** | URLs of related PRs surfaced in conversation, commits, or code. If none, **delete this subsection** (see Deletion rules). |
| **[AI] References** | Relevant docs/RFCs/library docs. AI-judged links (not seen verbatim in the conversation or diff) MUST include an inline `— reason` label explaining the relevance. If none, **delete this subsection** (see Deletion rules). |

#### Deletion rules for `[AI] Context`

- **Subsection-level deletion:** if `### Related PRs` or `### References` has no real entries, drop that subsection heading **and** its placeholder comment in full.
- **Section-level deletion:** if both subsections end up dropped, also drop the `## [AI] Context` heading and both surrounding `---` separators so the PR body has no empty Context section.
- **No placeholders.** Strings like `None.`, `N/A`, or empty bullet lists are not allowed in these subsections. Either a real entry exists, or the subsection is removed.

#### Hands off `[Human] Notes`

The `## [Human] Notes` section is reserved for the human author. Do not modify, fill, summarize into, or delete it. Ship it in the PR body exactly as it appears in the template — including its placeholder comment.

### Step 4: PR creation

**Title:** Write a natural, descriptive title that accurately represents the change. Do not use Conventional Commits format.

#### Priority: GitHub MCP

Use the `create_pull_request` MCP tool when available:

```
create_pull_request(
  owner: <repo owner>,
  repo: <repo name>,
  title: "<descriptive title>",
  body: "<filled template body>",
  head: "<current branch>",
  base: "main"
)
```

#### Fallback: gh CLI

If MCP is unavailable, use:

```bash
gh pr create --title "<descriptive title>" --base main --body "$(cat <<'EOF'
<filled template content>
EOF
)"
```
