#!/usr/bin/env bash
# Shared runner for the composite GitHub Action (action.yml).
# Inputs arrive as INPUT_* environment variables (see action.yml).
# Expects `agentsec` to be on PATH. Writes GitHub step outputs to $GITHUB_OUTPUT
# when that file is set. Exit 0 = all clean, 1 = findings, 2 = usage/tool error.
set -u

die() { echo "agentsec action: $*" >&2; exit 2; }

TOOLS_RAW="${INPUT_TOOLS:-resultguard,secretflow,piiguard,pathfence,shellfence,fetchfence}"
FAIL_ON="${INPUT_FAIL_ON:-high}"
PATHS_RAW="${INPUT_PATHS:-.}"
EXTRA_RAW="${INPUT_EXTRA_ARGS:-}"
SARIF="${INPUT_SARIF:-true}"
SARIF_DIR="${INPUT_SARIF_DIR:-agentsec-sarif}"
MCP_SNAPSHOT="${INPUT_MCP_SNAPSHOT:-}"
MCP_LOCK="${INPUT_MCP_LOCK:-}"

if ! command -v agentsec >/dev/null 2>&1; then
  die "agentsec is not on PATH (install the action repository with pip first)"
fi

mkdir -p "$SARIF_DIR"

# Cache --help text so we don't spawn the same tool twice just to probe flags.
declare -A HELP_CACHE=()
tool_help() {
  local tool="$1"
  if [[ -z "${HELP_CACHE[$tool]+x}" ]]; then
    HELP_CACHE[$tool]="$(agentsec "$tool" --help 2>&1 || true)"
  fi
  printf '%s' "${HELP_CACHE[$tool]}"
}

supports_flag() {
  local tool="$1" flag="$2"
  tool_help "$tool" | grep -q -- "$flag"
}

# Split a string on whitespace into a bash array name passed as $1.
read_ws_array() {
  local __name="$1" __src="$2"
  local -a __tmp=()
  # shellcheck disable=SC2206
  __tmp=( $__src )
  eval "$__name"='("${__tmp[@]}")'
}

FAILED=()
ERRORED=()
RAN=()

run_tool() {
  local tool="$1"
  shift
  local -a args=( "$@" )
  local outfile=""
  local rc=0

  if [[ "$SARIF" == "true" ]]; then
    if supports_flag "$tool" --sarif; then
      args+=(--sarif)
      outfile="$SARIF_DIR/${tool}.sarif"
    elif supports_flag "$tool" --json; then
      args+=(--json)
      outfile="$SARIF_DIR/${tool}.json"
    fi
  fi

  echo "::group::agentsec $tool"
  echo "+ agentsec $tool ${args[*]}"
  if [[ -n "$outfile" ]]; then
    agentsec "$tool" "${args[@]}" > "$outfile"
    rc=$?
    echo "wrote $outfile ($(wc -c < "$outfile") bytes)"
  else
    agentsec "$tool" "${args[@]}"
    rc=$?
  fi
  echo "exit $rc"
  echo "::endgroup::"

  RAN+=("$tool")
  if [[ $rc -eq 0 ]]; then
    return 0
  elif [[ $rc -eq 1 ]]; then
    FAILED+=("$tool")
  else
    ERRORED+=("$tool")
  fi
}

IFS=',' read -ra TOOL_ITEMS <<< "$TOOLS_RAW"
read_ws_array PATHS "$PATHS_RAW"
read_ws_array EXTRA "$EXTRA_RAW"

for raw in "${TOOL_ITEMS[@]}"; do
  tool="${raw// /}"
  [[ -n "$tool" ]] || continue

  if [[ "$tool" == "toolpin" ]]; then
    if [[ -z "$MCP_SNAPSHOT" || -z "$MCP_LOCK" ]]; then
      die "toolpin requires the mcp-snapshot and mcp-lock inputs"
    fi
    targs=( check "$MCP_SNAPSHOT" -l "$MCP_LOCK" )
    if supports_flag "$tool" --fail-on; then
      targs+=(--fail-on "$FAIL_ON")
    fi
    if [[ ${#EXTRA[@]} -gt 0 ]]; then
      targs+=("${EXTRA[@]}")
    fi
    run_tool "$tool" "${targs[@]}"
    continue
  fi

  if [[ ${#PATHS[@]} -eq 0 ]]; then
    die "no paths given for $tool"
  fi
  targs=( "${PATHS[@]}" )
  if supports_flag "$tool" --fail-on; then
    targs+=(--fail-on "$FAIL_ON")
  fi
  if [[ ${#EXTRA[@]} -gt 0 ]]; then
    targs+=("${EXTRA[@]}")
  fi
  run_tool "$tool" "${targs[@]}"
done

if [[ ${#RAN[@]} -eq 0 ]]; then
  die "no tools to run (tools input was empty or unparseable)"
fi

join_by_comma() {
  local IFS=,
  echo "$*"
}

if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  echo "sarif-dir=$SARIF_DIR" >> "$GITHUB_OUTPUT"
  echo "failed-tools=$(join_by_comma "${FAILED[@]}")" >> "$GITHUB_OUTPUT"
  echo "error-tools=$(join_by_comma "${ERRORED[@]}")" >> "$GITHUB_OUTPUT"
  echo "ran-tools=$(join_by_comma "${RAN[@]}")" >> "$GITHUB_OUTPUT"
fi

if [[ ${#ERRORED[@]} -gt 0 ]]; then
  echo "agentsec action: tools failed with a usage or runtime error: ${ERRORED[*]}" >&2
  exit 2
fi
if [[ ${#FAILED[@]} -gt 0 ]]; then
  echo "agentsec action: findings at or above --fail-on $FAIL_ON: ${FAILED[*]}" >&2
  exit 1
fi
exit 0
