## Runpod and Vast.ai CLI auth strategy

- Mount host config for persistent auth as a first-class path (`~/.runpod/config.toml` → `/home/node/.runpod/config.toml`, `~/.config/vastai/vast_api_key` → `/home/node/.config/vastai/vast_api_key`).
- Keep `RUNPOD_API_KEY` / `VAST_API_KEY` in the env passthrough list for ephemeral or scripted sessions.
- Prefer dedicated, least-privilege keys (Vast.ai allows scoped keys) rather than reusing a broad personal key.
- Only mount `.runpod/ssh` when the workflow explicitly needs Runpod SSH artifacts; otherwise keep the scope to `config.toml`.
