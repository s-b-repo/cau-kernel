#!/usr/bin/env bash
# Render the release notes for a version from the commit log.
#
# Usage: release-notes.sh VERSION OUTPUT
#
# This repository has no changelog, so the notes are what the commits say: each
# commit's subject and the explanation it was made with. That is the project's
# own account of the release, in the words its author wrote it.
#
# The notes carry what an operator needs and not only what changed:
#
#   * the version, the date and the comparison with the previous release,
#   * every commit since the last release, with its explanation,
#   * how to check what was downloaded.
set -euo pipefail

[ "$#" -eq 2 ] || {
    echo "usage: $0 VERSION OUTPUT" >&2
    exit 2
}
version=$1
output=$2

# The release before this one, if there is one: the notes say what changed
# since it. A first release has no previous tag, which is not an error.
previous=$(git tag --sort=-v:refname | grep -v "^v${version}$" | head -1 || true)
if [ -n "$previous" ]; then
    range="${previous}..v${version}"
else
    range="v${version}"
fi

{
    echo "# cau-kernel ${version}"
    echo
    echo "The kernel sensor: it reads the kernel's state and, in its eBPF build,"
    echo "acts on it. The engine that reads the log is a separate project"
    echo "([cau](https://github.com/s-b-repo/cau))."
    echo
    echo "## What changed"
    echo
    # Each commit's subject as a heading and its explanation as the body.
    git log --no-merges --reverse --format='### %s%n%n%b' "$range" |
        awk '{
            line = $0
            if (line ~ /^### /) {
                if (printed) { print "" }
                print line
                printed = 1
                next
            }
            # A commit with no body of its own says nothing more than its
            # subject; the blank lines that follow would only pad the notes.
            if (printed && line == "") { blanks++; next }
            if (blanks && line != "") { blanks = 0 }
            print line
        }'
    echo
    echo "## Checking what you downloaded"
    echo
    echo "Every asset in this release is listed in \`SHA256SUMS\`."
    echo
    echo '```'
    echo "sha256sum --ignore-missing -c SHA256SUMS"
    echo '```'
    echo
    echo "The sensor and the BPF-LSM objects it loads belong together: an"
    echo "operator who installs the binary without the matching objects has a"
    echo "sensor that cannot enforce anything, so both are in this release and"
    echo "both are in the manifest."
    echo
    echo "The notes above are the history itself: every commit's own account of"
    echo "what it changed and why."
    echo
    if [ -n "$previous" ]; then
        echo "Comparison with the previous release: <https://github.com/s-b-repo/cau-kernel/compare/${previous}...v${version}>."
    fi
    echo "Full history: <https://github.com/s-b-repo/cau-kernel/commits/v${version}>."
} > "$output"

if [ ! -s "$output" ]; then
    echo "release-notes: the notes are empty" >&2
    exit 1
fi

echo "release-notes: wrote $output ($(wc -l < "$output") lines)"
