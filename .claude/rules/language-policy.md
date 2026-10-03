## Language Policy

### Conversational Language

Mirror the user's input language in all conversational responses. If the user writes in Japanese, reply in Japanese. If the user writes in English, reply in English. Follow each message independently — do not lock to an earlier language if the user switches.

### Output Language

Produce all deliverables (code comments, documentation, generated files, commit messages, PR descriptions, reports) in the language resolved by the following priority order.

### Priority Order

1. An explicit instruction in the current message ("write the docs in French") overrides everything.
2. The most recent explicit instruction in the conversation applies to subsequent outputs until changed.
3. A project-level declaration in the project's `CLAUDE.md` (see format below).
4. When none of the above applies, default to English.

### Per-Project Configuration

To set the output language for a specific project, add the following block anywhere in the project's `.claude/CLAUDE.md`:

```
## Output Language

output-language: English
```

Replace `English` with the desired language (e.g., `Japanese`, `French`, `German`).
When this block is present, treat it as a standing instruction for all outputs in that project until overridden by a higher-priority rule.

### Scope

This policy applies to all text Claude generates: inline comments, docstrings, markdown files, CLI output strings, and any other human-readable content in deliverables.
