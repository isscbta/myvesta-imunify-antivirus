#!/bin/bash
# info: update myvesta-imunify-antivirus and the ImunifyAV signatures
# options: NONE
#
# Pulls the latest version of this repository, re-installs the commands and
# functions with imav-install.sh --update, and updates the ImunifyAV malware
# signatures.

REPO_DIR=$(cd "$(dirname "$0")" && pwd)

if [ "$(id -u)" -ne 0 ]; then
    echo "- Error: this script must be run as root" >&2
    exit 1
fi

if [ -d "$REPO_DIR/.git" ] && command -v git >/dev/null 2>&1; then
    echo "= Updating the repository in $REPO_DIR"
    git -C "$REPO_DIR" pull --ff-only || { echo "- Error: git pull failed" >&2; exit 1; }
else
    echo "= $REPO_DIR is not a git clone, using the files as they are"
fi

bash "$REPO_DIR/imav-install.sh" --update || exit 1

if command -v imunify-antivirus >/dev/null 2>&1; then
    echo "= Updating ImunifyAV malware signatures"
    imunify-antivirus update >/dev/null 2>&1 || echo "- Warning: signature update failed"
    echo "= ImunifyAV $(imunify-antivirus version 2>/dev/null | head -n 1)"
fi

echo
echo "==============================="
echo "myvesta-imunify-antivirus update completed."
echo "==============================="
