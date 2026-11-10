# mcpbundle

Offline auditor for **MCP server packaging manifests**: MCP Bundle `manifest.json`
files (inside a `.mcpb` archive, the legacy `.dxt` format, or loose) and MCP Registry
`server.json` entries.

These are the files an MCP server author ships so a client can install the server in
one click. The client trusts them to decide what command to run, which package
version to fetch, which settings to ask the user for, and where to send tokens.
**mcpbundle** reads them before you install or publish and flags inline secrets,
credential prompts that are not marked sensitive, shell-wrapped or pipe-to-shell
launch commands, unpinned packages, cleartext or internal remotes, privileged
container arguments, whole-disk directory defaults, injection-shaped tool text, and
missing provenance.

Standard library only. It never installs anything, never extracts archives to disk
(it reads `manifest.json` from the zip in memory), and never contacts a registry.

## How it differs from siblings

| Tool | Surface |
|---|---|
| **mcpbundle** | What an MCP server *publishes* for installation (`manifest.json`, `server.json`) |
| mcpposture | MCP *client* config files after installation (`mcp.json`, `claude_desktop_config.json`) |
| mcpoauth | OAuth discovery metadata a remote MCP server serves |
| toolpoison / toolpin | Live `tools/list` output (poisoning, drift) |
| aibom | Inventory of AI components across a whole repo |

## Rules

| Rule | Severity | What it flags |
|---|---|---|
| MB01 | critical | Secret-shaped literal in `env`, a `user_config` default, an environment-variable or header `value`/`default`, or URL userinfo (masked in output) |
| MB02 | high | Credential-like `user_config` without `"sensitive": true`, or a credential-like environment variable / header without `is_secret` |
| MB03 | high / critical | Launch through `sh -c`, `bash -c`, `cmd /c`, `powershell -Command`, or a shell `runtime_hint`; critical when a download is piped into an interpreter (`curl ... \| bash`, `irm ... \| iex`) |
| MB04 | high / medium | Unpinned package: `npx`/`uvx` without an exact version, registry `version` missing/`latest`/range, untagged container image; medium for an `mcpb` package with no `file_sha256` |
| MB05 | high | `http://` remote, transport, or registry URL on a non-loopback host |
| MB06 | high | `--privileged`, `--network/--pid/--ipc host`, `--cap-add`, unconfined security options, or mounting `/`, `/etc`, `/root`, `/home`, `~` or `docker.sock` |
| MB07 | medium | Directory default or argument of `/`, `~`, `$HOME`, `C:\`, `%USERPROFILE%` |
| MB08 | medium / high | Injection-shaped phrases in tool, prompt, setting or server descriptions; high for hidden zero-width, bidi or TAG Unicode |
| MB09 | medium / high | Remote on a private, internal-suffix, or link-local address; high for cloud metadata |
| MB10 | low | Missing provenance (author, repository, license for bundles; repository for `server.json`) |
| MB11 | low | `tools_generated` / `prompts_generated` set, so the declared list is not the full surface |
| MB12 | info | Inventory line per manifest |

Both `snake_case` and `camelCase` registry field names are accepted
(`registry_type`/`registryType`, `is_secret`/`isSecret`, and so on).

## Usage

```sh
python3 mcpbundle.py examples/risky                 # text report, exit 1 (high+ findings)
python3 mcpbundle.py examples/clean --min-severity low
python3 mcpbundle.py my-server.mcpb                 # reads manifest.json from the archive
python3 mcpbundle.py . --json                       # walk a repo for manifest.json / server.json
python3 mcpbundle.py server.json --sarif > mcpbundle.sarif
cat server.json | python3 mcpbundle.py -
python3 mcpbundle.py --list-rules
```

Options: `--json`, `--sarif`, `--min-severity`, `--fail-on` (default `high`; `none`
always exits 0), `--disable MB10,MB11`. Exit codes: 0 clean, 1 findings at or above
`--fail-on`, 2 usage or input error.

## Example

```text
$ python3 mcpbundle.py examples/risky/manifest.json
examples/risky/manifest.json:13  CRITICAL MB01  env FILES_API_TOKEN ships a literal secret (FAKE…****)  [/server/mcp_config/env/FILES_API_TOKEN]
examples/risky/manifest.json:11  CRITICAL MB03  downloads and pipes into an interpreter  [/server/mcp_config]
examples/risky/manifest.json:19  HIGH     MB02  credential-like setting 'api_key' is not marked "sensitive": true (stored and shown in plaintext)  [/user_config/api_key]
examples/risky/manifest.json:23  MEDIUM   MB08  injection-shaped phrase: 'Before using any other tool'  [/tools/0/description]
...
```

All secrets in `examples/` are obviously fake (`FAKE-EXAMPLE-...`).

## Known limits

- **Static review only.** A manifest that passes can still ship a malicious
  `server/index.js`; mcpbundle does not read or execute server code (use `mcpsink`
  for Python MCP server source).
- Secret detection is name- and shape-based; it misses secrets with innocuous names
  and may flag long non-secret values under credential-like names.
- Injection detection is a small phrase list plus hidden-Unicode checks, not a model.
- It does not check that a package version actually exists, that `file_sha256`
  matches the archive, or that the `repository` is genuine.
- Only the first `manifest.json` (shallowest path) in an archive is read.
