#!/usr/bin/env bash
set -euo pipefail

# Usage: ./build.sh <tag-name>
TAG="${1:-}"

if [ -z "$TAG" ]; then
  echo "Usage: $0 <tag-name>"
  exit 1
fi

# Use the folder defined in $root, or the current directory if not provided
ROOT="$PWD"

echo ">> ROOT = $ROOT"
echo ">> Release tag = $TAG"

cd "$ROOT"

# 1. Check if the coreruleset directory exists, otherwise clone it
if [ ! -d "coreruleset" ]; then
  echo ">> Cloning coreruleset..."
  git clone https://github.com/coreruleset/coreruleset.git
else
  echo ">> coreruleset directory already exists."
fi

# 2. git fetch inside coreruleset
cd "$ROOT/coreruleset"
echo ">> Fetching latest git information..."
git fetch --tags origin

# 3. Switch to the most recent tag
echo ">> Finding the latest tag..."
LAST_TAG="$(git describe --tags "$(git rev-list --tags --max-count=1)" || true)"

if [ -z "$LAST_TAG" ]; then
  echo "!! No tags found in the coreruleset repository."
  exit 1
fi

echo ">> Checking out tag: $LAST_TAG"
git checkout "$LAST_TAG"

# 4. Synchronize $root/coreruleset/rules/** into $root/rules/crs
echo ">> Synchronizing rules into $ROOT/rules/crs..."
mkdir -p "$ROOT/rules/crs"

# --delete makes the target directory exactly match the source
rsync -av --delete "$ROOT/coreruleset/rules/" "$ROOT/rules/crs/"

# 5. Run the go build command in $root
cd "$ROOT"
echo ">> Building WASM binary coraza.wasm..."
GOOS=wasip1 GOARCH=wasm go build -o "coraza-${TAG}.wasm" coraza.go

#6. Compute SHA-256 of the final coraza.wasm
echo ">> Computing SHA-256 for coraza.wasm..."
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "coraza-${TAG}.wasm" | tee "coraza-${TAG}.wasm.sha256"
elif command -v shasum >/dev/null 2>&1; then
  shasum -a 256 "coraza-${TAG}.wasm" | tee "coraza-${TAG}.wasm.sha256"
else
  echo "!! Neither sha256sum nor shasum is available. Cannot compute SHA-256."
  exit 1
fi

# 7. Commit all changes after the build (only if there is something to commit)
echo ">> Checking for changes to commit..."
if [ -n "$(git status --porcelain)" ]; then
  echo ">> Staging all changes..."
  git add .

  echo ">> Committing changes..."
  git commit -am "chore(deps): bump coreruleset to $LAST_TAG"
else
  echo ">> No changes to commit."
fi

# 8. Create a tag on the project
echo ">> Creating git tag: ${TAG}"
# If the tag already exists, this will fail; adjust to your workflow if needed
git tag -a "${TAG}" -m "Release ${TAG}"
git push origin main
git push origin --tags

echo ">> All done. Tag '${TAG}' created."
