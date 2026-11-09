#!/usr/bin/env bash
# Creates the GitHub repo and pushes this project.
# Usage: ./scripts/publish_github.sh [repo-name] [--public|--private]
set -euo pipefail
cd "$(dirname "$0")/.."

NAME="${1:-agentpass}"
VISIBILITY="${2:---public}"

if ! command -v gh >/dev/null 2>&1; then
  echo "GitHub CLI not found. Install it with:  brew install gh"
  exit 1
fi
if ! gh auth status >/dev/null 2>&1; then
  echo "Log in to GitHub first (one time):"
  gh auth login
fi

if [ ! -d .git ]; then
  git init -b main
fi
git add -A
if ! git diff --cached --quiet; then
  git commit -m "AgentPass: identity, permission and audit gateway for AI agents"
fi

if git remote get-url origin >/dev/null 2>&1; then
  git push -u origin main
else
  gh repo create "$NAME" "$VISIBILITY" --source=. --remote=origin --push \
    --description "Identity, permission and audit gateway for AI agents (Python)"
fi

echo
echo "Published: $(gh repo view --json url -q .url)"
