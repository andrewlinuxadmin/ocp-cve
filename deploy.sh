#!/usr/bin/env bash
#
# Updates the source code on `main` and republishes the production build on
# the `gh-pages` branch (served via GitHub Pages).
#
# Usage:
#   ./deploy.sh ["commit message for source changes"]
#
# - If there are uncommitted changes, they are committed with the given
#   message (or a default one) and pushed to `main`.
# - The app is rebuilt and the `dist/` output is published to `gh-pages`
#   using a temporary git worktree, without touching your working directory.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"

REMOTE="origin"
SOURCE_BRANCH="main"
PAGES_BRANCH="gh-pages"
BUILD_DIR="dist"
COMMIT_MESSAGE="${1:-"Update source ($(date -u +"%Y-%m-%dT%H:%M:%SZ"))"}"

log() { printf '\n\033[1;34m==> %s\033[0m\n' "$1"; }

# --- 1. Commit and push source code changes -------------------------------

log "Checking for source changes on $SOURCE_BRANCH"
if [[ -n "$(git status --porcelain)" ]]; then
  git add -A
  git commit -m "$COMMIT_MESSAGE"
else
  echo "No local changes to commit."
fi

log "Pushing $SOURCE_BRANCH to $REMOTE"
git push "$REMOTE" "$SOURCE_BRANCH"

# --- 2. Build the app -------------------------------------------------------

log "Installing dependencies and building"
npm install
npm run build

# --- 3. Publish dist/ to gh-pages ------------------------------------------

WORKTREE_DIR="$(mktemp -d)"
cleanup() { git worktree remove "$WORKTREE_DIR" --force >/dev/null 2>&1 || true; }
trap cleanup EXIT

log "Preparing $PAGES_BRANCH worktree"
git fetch "$REMOTE" "$PAGES_BRANCH" >/dev/null 2>&1 || true
git worktree add --detach "$WORKTREE_DIR" >/dev/null

(
  cd "$WORKTREE_DIR"

  if git ls-remote --exit-code --heads "$REMOTE" "$PAGES_BRANCH" >/dev/null 2>&1; then
    git checkout -B "$PAGES_BRANCH" "$REMOTE/$PAGES_BRANCH"
    git rm -rf . -q
  else
    git checkout --orphan "$PAGES_BRANCH"
    git rm -rf . -q 2>/dev/null || true
  fi

  cp -r "$OLDPWD/$BUILD_DIR/." .
  touch .nojekyll

  git add -A
  if git diff --cached --quiet; then
    echo "gh-pages is already up to date, nothing to publish."
  else
    git commit -m "Deploy build ($(date -u +"%Y-%m-%dT%H:%M:%SZ"))"
    log "Pushing $PAGES_BRANCH to $REMOTE"
    git push "$REMOTE" "$PAGES_BRANCH"
  fi
)

log "Done. Site: https://andrewlinuxadmin.github.io/ocp-cve/"
