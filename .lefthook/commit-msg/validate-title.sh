#!/usr/bin/env bash
set -euo pipefail

commit_msg_file="$1"
title=$(head -n 1 "$commit_msg_file")

# Allow merge commits
if [[ "$title" =~ ^Merge ]]; then
  exit 0
fi

# Format: <type>(<scope>): <subject>
#   type:    required (feat|fix|docs|style|refactor|perf|test|chore)
#   scope:   optional
#   subject: required
pattern='^(feat|fix|docs|style|refactor|perf|test|chore)(\([^)]+\))?: .+$'

if [[ ! "$title" =~ $pattern ]]; then
  echo "ERROR: commit message title does not match the required format."
  echo ""
  echo "  Expected: <type>(<scope>): <subject> (<issue-ref>)"
  echo "  Got:      $title"
  echo ""
  echo "  type:  feat|fix|docs|style|refactor|perf|test|chore"
  echo "  scope: optional (e.g. auth, api)"
  echo "  issue: required (e.g. #123)"
  echo ""
  echo "  Examples:"
  echo "    feat(auth): add OAuth2 support (#123)"
  echo "    fix: handle null response (#42)"
  exit 1
fi
