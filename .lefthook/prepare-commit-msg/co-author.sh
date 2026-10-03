#!/usr/bin/env bash
set -euo pipefail

# Append `Co-Authored-By: <git config user>` unless the current author
# already IS that user, or the trailer is present, or this is a
# merge/squash where a trailer would be noise.

msg_file="$1"
msg_source="${2:-}"

# Skip merges and squashes — a Co-Authored-By trailer there is misleading.
case "$msg_source" in
  merge | squash) exit 0 ;;
esac

# The co-author target is whoever the user is per git config.
co_name=$(git config --get user.name || true)
co_email=$(git config --get user.email || true)
[ -z "$co_name" ] && exit 0
[ -z "$co_email" ] && exit 0

# Effective author for this commit. GIT_AUTHOR_* env overrides git config.
author_name="${GIT_AUTHOR_NAME:-$co_name}"
author_email="${GIT_AUTHOR_EMAIL:-$co_email}"

# Skip when author already matches the co-author (nothing to co-attribute).
if [ "$author_name" = "$co_name" ] && [ "$author_email" = "$co_email" ]; then
  exit 0
fi

# Skip when a matching trailer is already present (e.g. --amend, template).
if grep -Fqi "Co-Authored-By: $co_name <$co_email>" "$msg_file"; then
  exit 0
fi

printf '\nCo-Authored-By: %s <%s>\n' "$co_name" "$co_email" >>"$msg_file"
