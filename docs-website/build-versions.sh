#!/bin/bash
set -e

# Navigate to the docs-website directory
cd "$(dirname "$0")"

echo "Building Docusaurus versions from docs/* branches..."

# Clean up any existing versioned generated folders
rm -rf versioned_docs versioned_sidebars versions.json
mkdir -p versioned_docs versioned_sidebars

# Initialize versions array
VERSIONS=()

# Fetch docs branches (adjust 'origin' if your remote is named differently)
git fetch origin '+refs/heads/docs/*:refs/remotes/origin/docs/*' || true

# Find all branches matching 'docs/*'
BRANCHES=$(git branch -r | grep 'origin/docs/' | sed 's/^[[:space:]]*origin\///' || true)

for branch in $BRANCHES; do
  # Only treat docs/X.Y.Z branches as version snapshots.
  if ! [[ "$branch" =~ ^docs/[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "Skipping non-version docs branch: $branch"
    continue
  fi

  # Extract version number (e.g., docs/0.7.0 -> 0.7.0)
  VERSION=${branch#docs/}
  echo "Processing version: $VERSION from branch: $branch"

  # Create the target directory for this version's docs
  TARGET_DIR="versioned_docs/version-$VERSION"
  mkdir -p "$TARGET_DIR"
  
  # Extract the 'docs/' folder from that specific branch
  # using git archive so we don't have to switch branches
  if ! (cd .. && git archive "$branch" docs/) | tar -x -C "$TARGET_DIR"; then
    echo "Warning: Could not extract docs/ from $branch. Skipping version $VERSION."
    rm -rf "$TARGET_DIR"
    continue
  fi

  # Extract the sidebars file for this version.
  # Docusaurus expects this in versioned_sidebars/version-{version}-sidebars.js
  if ! git show "$branch:docs-website/sidebars.js" > "versioned_sidebars/version-${VERSION}-sidebars.js" 2>/dev/null; then
    echo "Warning: Could not extract sidebars.js from $branch. Skipping version $VERSION."
    rm -rf "$TARGET_DIR"
    rm -f "versioned_sidebars/version-${VERSION}-sidebars.js"
    continue
  fi

  VERSIONS+=("$VERSION")
  
  # Extract README.md and CONTRIBUTING.md if they are included in the docs config
  git show "$branch:README.md" > "$TARGET_DIR/README.md" || true
  git show "$branch:CONTRIBUTING.md" > "$TARGET_DIR/CONTRIBUTING.md" || true
done

# Generate versions.json for Docusaurus to read
if [ ${#VERSIONS[@]} -gt 0 ]; then
  # Write the versions array as a JSON list using jq or basic Node/Python string manipulation
  # Quick inline node script to write a valid JSON array
  node -e "const fs=require('fs'); fs.writeFileSync('versions.json', JSON.stringify(process.argv.slice(1)));" "${VERSIONS[@]}"
  echo "versions.json generated with: ${VERSIONS[*]}"
else
  echo "[]" > versions.json
  echo "No docs/* branches found. Generating empty versions.json."
fi
