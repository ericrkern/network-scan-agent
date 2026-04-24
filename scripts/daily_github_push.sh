#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="/home/jetson/Documents/.Network"
LOG_FILE="/home/jetson/Documents/.Network/deep_scan_cron.log"

cd "$REPO_DIR"

# Ensure we commit with a stable identity without modifying git config.
export GIT_AUTHOR_NAME="Eric Kern"
export GIT_AUTHOR_EMAIL="eric@ericrkern.com"
export GIT_COMMITTER_NAME="Eric Kern"
export GIT_COMMITTER_EMAIL="eric@ericrkern.com"

# Keep local main in sync before committing new scan artifacts.
git fetch origin main >>"$LOG_FILE" 2>&1 || true
git pull --rebase origin main >>"$LOG_FILE" 2>&1 || true

if [[ -z "$(git status --porcelain)" ]]; then
  echo "$(date '+%Y-%m-%d %H:%M:%S') [auto-push] no changes to commit" >>"$LOG_FILE"
  exit 0
fi

git add -A
git commit -m "Auto-update daily website/network data snapshot." >>"$LOG_FILE" 2>&1
git push origin main >>"$LOG_FILE" 2>&1

echo "$(date '+%Y-%m-%d %H:%M:%S') [auto-push] pushed latest changes" >>"$LOG_FILE"
