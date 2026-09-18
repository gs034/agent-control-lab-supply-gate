#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Fail-closed Lab-only check: reconstructed brand tokens must not appear
# in the tracked tree, path names, branch name, or commit subjects/bodies
# on this branch (versus main). Plugin4Shell-class wording is allowed.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "${ROOT}" ]]; then
  echo "lab-only: not a git checkout" >&2
  exit 1
fi
cd "${ROOT}"

if ! command -v rg >/dev/null 2>&1; then
  echo "lab-only: rg (ripgrep) is required" >&2
  exit 1
fi

# Split so this file does not contain the brand strings as literals.
TOKENS=(
  "AE""GIS"
  "Cap""Scope"
  "AG""F"
  "Cygnet""Quant"
  "Sig""net"
  "Excali""VAR"
  "AI""PTH"
  "think""money"
  "Fal""con"
  "PIPE""LINE"
  "C""Q"
)

RG_ARGS=()
for token in "${TOKENS[@]}"; do
  RG_ARGS+=(-e "${token}")
done

rg_hit() {
  # 0 = match (forbidden), 1 = clean, 2+ = tool error
  rg -n -i -w --hidden --glob '!.git/**' "${RG_ARGS[@]}" "$@"
}

fail_if_hit() {
  local label="$1"
  shift
  local code=0
  set +e
  rg_hit "$@"
  code=$?
  set -e
  if [[ "${code}" -eq 0 ]]; then
    echo "lab-only: forbidden brand token in ${label}" >&2
    exit 1
  fi
  if [[ "${code}" -ge 2 ]]; then
    echo "lab-only: rg failed while scanning ${label}" >&2
    exit 1
  fi
}

self_test() {
  local tmp token
  tmp="$(mktemp -d)"
  for token in "${TOKENS[@]}"; do
    printf '%s\n' "${token}" >"${tmp}/probe.txt"
    if ! rg -q -i -w -e "${token}" "${tmp}/probe.txt"; then
      rm -rf "${tmp}"
      echo "lab-only: self-test miss for a reconstructed token" >&2
      exit 1
    fi
  done
  printf '%s\n' "Plugin4Shell-class threat pattern" >"${tmp}/ok.txt"
  if rg -q -i -w "${RG_ARGS[@]}" "${tmp}/ok.txt"; then
    rm -rf "${tmp}"
    echo "lab-only: self-test false positive on Plugin4Shell-class" >&2
    exit 1
  fi
  rm -rf "${tmp}"
}

self_test

fail_if_hit "working tree" .

mapfile -t TRACKED < <(git ls-files)
if [[ "${#TRACKED[@]}" -eq 0 ]]; then
  echo "lab-only: no tracked files" >&2
  exit 1
fi

fail_if_hit "tracked file contents" -- "${TRACKED[@]}"

fail_if_hit "tracked path names" -- <<<"$(printf '%s\n' "${TRACKED[@]}")"

branch="${GITHUB_HEAD_REF:-}"
if [[ -z "${branch}" ]]; then
  branch="$(git branch --show-current || true)"
fi
if [[ -z "${branch}" ]]; then
  branch="${GITHUB_REF_NAME:-}"
fi
if [[ -n "${branch}" ]]; then
  fail_if_hit "branch name '${branch}'" -- <<<"${branch}"
fi

base=""
if git rev-parse --verify --quiet origin/main >/dev/null; then
  base="origin/main"
elif git rev-parse --verify --quiet main >/dev/null; then
  base="main"
fi
if [[ -n "${base}" ]] && [[ "$(git rev-parse HEAD)" != "$(git rev-parse "${base}")" ]]; then
  commits="$(git log --format='%s%n%b' "${base}..HEAD")"
  if [[ -n "${commits}" ]]; then
    fail_if_hit "commit subjects/bodies (${base}..HEAD)" -- <<<"${commits}"
  fi
fi

echo "lab-only: clean"
