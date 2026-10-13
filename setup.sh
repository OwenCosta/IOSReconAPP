#!/usr/bin/env bash
# One-shot setup on a Mac: installs XcodeGen if needed, generates ReconKit.xcodeproj and opens it.
set -euo pipefail
cd "$(dirname "$0")"
command -v xcodegen >/dev/null 2>&1 || brew install xcodegen
xcodegen generate
echo "Generated ReconKit.xcodeproj"
open ReconKit.xcodeproj
