#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Fail-closed Lab brand-wall: reconstructed brand tokens, spaced brand
# forms, SKU language, provenance phrases, and commercial path prefixes
# must not appear in the tracked tree, path names, branch name, or commit
# subjects/bodies. Plugin4Shell-class wording is allowed.
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
WORD_TOKENS=(
  "AE""GIS"
  "Cap""Scope"
  "AG""F"
  "Cygnet""Quant"
  "Sig""net""Quant"
  "Sig""net"
  "Excali""VAR"
  "AI""PTH"
  "think""money"
  "Fal""con"
  "PIPE""LINE"
  "C""Q"
)

PHRASES=(
  "Cygnet"" Quant"
  "Sig""net"" Quant"
  "Think"" Money"
  "C""Q"" SKU"
  "C""Q""-SKU"
)

PROVENANCE_RE=(
  'ip[-_[:space:]]+transfer'
  'acquired[-_[:space:]]+from'
)

PATH_PREFIXES=(
  "cygnet""quant"
  "think""money"
)

WORD_ARGS=()
for token in "${WORD_TOKENS[@]}"; do
  WORD_ARGS+=(-e "${token}")
done

PHRASE_ARGS=()
for token in "${PHRASES[@]}"; do
  PHRASE_ARGS+=(-e "${token}")
done

PROV_ARGS=()
for token in "${PROVENANCE_RE[@]}"; do
  PROV_ARGS+=(-e "${token}")
done

PATH_ARGS=()
for prefix in "${PATH_PREFIXES[@]}"; do
  PATH_ARGS+=(-e "(^|/)${prefix}(/|$)")
done

fail_if_rg() {
  local label="$1"
  shift
  local code=0
  set +e
  rg -n -i --hidden --glob '!.git/**' "$@"
  code=$?
  set -e
  if [[ "${code}" -eq 0 ]]; then
    echo "lab-only: forbidden token or keep-out phrase in ${label}" >&2
    exit 1
  fi
  if [[ "${code}" -ge 2 ]]; then
    echo "lab-only: rg failed while scanning ${label}" >&2
    exit 1
  fi
}

scan_text_targets() {
  local label="$1"
  shift
  fail_if_rg "${label} (brands)" -w "${WORD_ARGS[@]}" "$@"
  fail_if_rg "${label} (phrases)" -w "${PHRASE_ARGS[@]}" "$@"
  fail_if_rg "${label} (provenance)" "${PROV_ARGS[@]}" "$@"
}

self_test() {
  local tmp token
  tmp="$(mktemp -d)"
  for token in "${WORD_TOKENS[@]}" "${PHRASES[@]}"; do
    printf '%s\n' "${token}" >"${tmp}/probe.txt"
    if ! rg -q -i -w -e "${token}" "${tmp}/probe.txt"; then
      rm -rf "${tmp}"
      echo "lab-only: self-test miss for a reconstructed token" >&2
      exit 1
    fi
  done
  printf '%s\n' "ip""-""trans""fer" >"${tmp}/prov1.txt"
  printf '%s\n' "acquir""ed from" >"${tmp}/prov2.txt"
  if ! rg -q -i "${PROV_ARGS[@]}" "${tmp}/prov1.txt" || ! rg -q -i "${PROV_ARGS[@]}" "${tmp}/prov2.txt"; then
    rm -rf "${tmp}"
    echo "lab-only: self-test miss for provenance phrases" >&2
    exit 1
  fi
  printf '%s/\n' "${PATH_PREFIXES[0]}" >"${tmp}/paths.txt"
  printf '%s/\n' "${PATH_PREFIXES[1]}" >>"${tmp}/paths.txt"
  if ! rg -q -i "${PATH_ARGS[@]}" "${tmp}/paths.txt"; then
    rm -rf "${tmp}"
    echo "lab-only: self-test miss for commercial path prefixes" >&2
    exit 1
  fi
  printf '%s\n' "Plugin4Shell-class threat pattern" >"${tmp}/ok.txt"
  if rg -q -i -w "${WORD_ARGS[@]}" "${tmp}/ok.txt" \
    || rg -q -i -w "${PHRASE_ARGS[@]}" "${tmp}/ok.txt" \
    || rg -q -i "${PROV_ARGS[@]}" "${tmp}/ok.txt"; then
    rm -rf "${tmp}"
    echo "lab-only: self-test false positive on Plugin4Shell-class" >&2
    exit 1
  fi
  rm -rf "${tmp}"
}

self_test

mapfile -t TRACKED < <(git ls-files)
if [[ "${#TRACKED[@]}" -eq 0 ]]; then
  echo "lab-only: no tracked files" >&2
  exit 1
fi

scan_text_targets "working tree" .
scan_text_targets "tracked file contents" -- "${TRACKED[@]}"

path_list="$(printf '%s\n' "${TRACKED[@]}")"
scan_text_targets "tracked path names" -- <<<"${path_list}"
fail_if_rg "tracked path prefixes" "${PATH_ARGS[@]}" -- <<<"${path_list}"

branch="${GITHUB_HEAD_REF:-}"
if [[ -z "${branch}" ]]; then
  branch="$(git branch --show-current || true)"
fi
if [[ -z "${branch}" ]]; then
  branch="${GITHUB_REF_NAME:-}"
fi
if [[ -n "${branch}" ]]; then
  scan_text_targets "branch name '${branch}'" -- <<<"${branch}"
  fail_if_rg "branch name path prefix '${branch}'" "${PATH_ARGS[@]}" -- <<<"${branch}"
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
    scan_text_targets "commit subjects/bodies (${base}..HEAD)" -- <<<"${commits}"
  fi
fi

echo "lab-only: clean"
