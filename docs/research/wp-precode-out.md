Completed the spike batch and cleanup. Log is at `/tmp/precode-changes.txt`; no full tokens were printed or logged.

**Verdicts**

1. **PASS**: Codex works fully contained through `--network=none` + `socat` + Unix-socket CONNECT proxy. `codex exec` returned `ok`. Proxy saw only CONNECTs, including `chatgpt.com:443`; with no network namespace, the WSS path necessarily honored proxying.

2. **PASS**: Podman honors file-over-dir bind overlay under `--userns=keep-id`. Dummy `/home/node/.claude/.credentials.json` was visible, while the real `~/.claude` directory remained writable.

3. **PASS/DATA**: Claude inject mode survives expired dummy OAuth. Claude tried OAuth refresh first, failed, attempted dead-token disk clear against the read-only overlay, then still completed via injected real token through `/v1/messages?beta=true`. No coved refresh handler is required for the container path; host token invalidity should become a host re-login error.

4. **PASS**: `socat` fork bridge held concurrency. `20/20` concurrent `curl https://github.com` requests returned HTTP `200`; proxy logged 20 CONNECTs.

5. **PASS/DATA**:
   - Codex minimal prompt allowlist: `chatgpt.com`; add `auth.openai.com` for refresh. Forced expired JWT confirmed refresh CONNECT to `auth.openai.com`.
   - Codex denied gracefully: `github.com`, `api.github.com`, `files.openai.com`, `ab.chatgpt.com`.
   - Claude inject minimal container egress: local reverse proxy only; reverse proxy needs `api.anthropic.com`.
   - Claude denied gracefully: `api.anthropic.com` bootstrap/refresh attempts, `platform.claude.com`, `http-intake.logs.us5.datadoghq.com`.

6. **DATA**

| runtime | clone+install wall | peak RSS | cold start median | est. max parallel in 7.5GB |
|---|---:|---:|---:|---:|
| `crun` | 5.174 s | 153,668 KiB / 150 MiB | 0.258 s | ~25-30 agent sessions |
| `runsc` | 8.483 s | 924,556 KiB / 903 MiB | 0.415 s | ~6-8 agent sessions |

**Implications**

Use the Codex socket-bridge design; Spike 1 passed cleanly. Use the Claude credential overlay plus injection design; expired dummy creds are noisy but survivable. Default to `crun` for many parallel low-friction YOLO sessions. Use `runsc` only when kernel-escape isolation is worth the measured cost: ~1.64x slower workload and ~6x sampled RSS in this run.

Cleanup confirmed: removed `cove-spike:latest`, `cove-spike*` containers, and `/tmp/cove-precode-spike`; no temp copied credentials remain under that path.