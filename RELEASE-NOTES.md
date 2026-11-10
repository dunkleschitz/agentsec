# agentsec v0.48.0

Offline, stdlib-only kit. 38 tools. This release generalizes detectors by class for independent red-team round 8 (issues #28–#36), then re-scores that set as seen. The original v0.47.0 unseen score stays the headline independent number. 2085 unit tests.

### Generalization (class-level, not fixture-specific instances)

Round 8 is the development set. Rules were extended around classes, checked on a private labeled dev set of new variants, then frozen before the round-8 fixtures were re-scored:

- **resultguard / toolpoison** — a concealed-document channel covering charset and markup that hides text: UTF-7, HTML/Markdown/LaTeX comment and conditional blocks, hidden or tiny CSS, Mermaid/PlantUML remote-image labels, and structured clinical/office narratives (FHIR/CDA/OOXML vanished text), with decode-and-rescan. Documentation that merely mentions UTF-7 or ordinary clinical text stays clean.
- **toolpoison** — annotation-vs-behavior contradictions (`readOnlyHint` / `destructiveHint` / a read-only title vs. destructive verbs in the name, description, or schema), including tokenized names such as `drop_namespace`. Defensive mentions of sensitive paths by a tool whose purpose is to manage them, and third-person discussion of attack phrases, are no longer TP03/TP01 false positives.
- **shellfence** — reverse tunnels (`ssh`/`autossh -R`, `RemoteForward`) and container/namespace escapes (`nsenter -t 1`, `chroot /proc/1/root`, `unshare` plus proc root) as a class. Ordinary `ssh` login and `-L` local forwards stay clean.
- **memfence** — memories that change trust or identity, pre-approve money movement, weaken security controls (2FA/MFA/confirmation), or route private data to an external sink (public issue/repo, SFTP/SCP export), including instructions buried in a style preference. “2FA is enabled” and “do not auto-approve payments without confirmation” stay clean.
- **fetchfence** — cloud-provider metadata hostnames as a class (`metadata.<provider-domain>`, IMDS paths), not a single Equinix hostname.
- **pathfence** — local messaging/mail databases (Messages, Mail, WhatsApp ChatStorage, and similar) and infra-access / backup-key stores (Teleport `tsh`, Borg, restic, kopia, and similar) as path classes.
- **mcpposture** — unpinned installers in more ecosystems (`gem exec`, `mise`/`rtx`/`asdf exec`, WSL-wrapped launchers), container runtime sockets (`containerd.sock`, `crio.sock`, `podman.sock` as well as `docker.sock`), and proxy-environment hijack (`HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` to a non-loopback host).
- **secretflow** — push-notification sinks as a class (`ntfy`, Pushover, Gotify, OneSignal, and similar).
- **mcpoauth** — look-alike authorization servers (typo/confusable of the resource host or of a well-known issuer) and over-broad first-party scopes (`*.all`, `mail.send`, `cloud-platform`). Narrow scopes such as `Mail.Read` stay clean. A well-known identity provider listed for a different app host is not treated as a look-alike.

### Benchmark

The headline independent number is still round 8 on frozen v0.47.0 detectors. Unseen F1 across successive independent rounds: 78.3 → 74.4 → 61.5 → 81.3 → 96.1 → 78.2.

| Set | P / R / F1 | Notes |
|---|---|---|
| Author corpus (125) | 100% / 100% / 100% | 76/0/0/49 |
| Held-out | 100% / 100% / 100% | 26/0/0/14 |
| Red-team round 1 (v0.40.0, unseen) | 93.8% / 85.7% / 89.6% | 60/4/10/26, frozen |
| Same round-1 set after later fixes | 100% / 100% / 100% | 70/0/0/30, labeled **seen** |
| Red-team round 2 (v0.41.0, unseen) | 80.4% / 38.9% / 52.5% | 37/9/58/30, frozen |
| Same round-2 set after later generalization | 100% / 100% / 100% | 95/0/0/39, labeled **seen** |
| Red-team round 3 (v0.43.0, unseen) | 97.3% / 65.5% / 78.3% | 36/1/19/28, frozen |
| Same round-3 set after later generalization | 100% / 100% / 100% | 55/0/0/29, labeled **seen** |
| Red-team round 4 (v0.44.0, unseen) | 97.0% / 60.4% / 74.4% | 32/1/21/26, frozen |
| Same round-4 set after later generalization | 100% / 100% / 100% | 53/0/0/27, labeled **seen** |
| Red-team round 5 (v0.45.0, unseen) | 96.0% / 45.3% / 61.5% | 24/1/29/26, frozen |
| Same round-5 set after later generalization | 100% / 100% / 100% | 53/0/0/27, labeled **seen** |
| Red-team round 6 (v0.46.0, unseen) | 97.4% / 69.8% / 81.3% | 37/1/16/26, frozen |
| Same round-6 set after later generalization | 100% / 100% / 100% | 53/0/0/27, labeled **seen** |
| Red-team round 7 (v0.47.0, unseen) | 100.0% / 92.5% / 96.1% | 49/0/4/27, scored **once** |
| Red-team round 8 (v0.47.0, unseen) | 95.6% / 66.2% / 78.2% | 43/2/22/33, frozen; **headline independent** |
| Same round-8 set after v0.48.0 generalization | 100.0% / 93.8% / 96.8% | 61/0/4/35, labeled **seen** |

Round 8 (`benchmarks/redteam8/`, 100 samples) was written against the frozen v0.47.0 detectors by a separate author who did not read tool source, tests, or prior fixtures. Detection-gap issues #28–#36 describe the misses. Fixes were designed from the issue text and a private dev set; the fixtures were not opened while designing rules, then the set was re-scored once as seen. Remaining honest seen misses: a FHIR narrative and a LaTeX `iffalse` channel that the concealed-document class did not extract, a trust/identity memory whose wording the new class did not match, and a push-notification hop whose tool name the sink class did not treat as outbound. Those four were left as-is. Closed #28–#36.

### Issues

Closed #28, #29, #30, #31, #32, #33, #34, #35, #36. Good-first-issues #1–#5 were not touched.
