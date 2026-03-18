---
title: npm install scripts disabled by default
date: 2026-03-19
status: accepted
---

`NPM_CONFIG_IGNORE_SCRIPTS=true` is set in both Dockerfile and Dockerfile.gpu-amd.

This follows the Trail of Bits npm supply chain hardening recommendations. Postinstall scripts are the primary vector for npm supply chain attacks — a compromised or typosquatted package can run arbitrary code at `npm install` time.

Since cove runs AI tools in fully autonomous mode (`--dangerously-skip-permissions`, `--yolo`), the tools freely run `npm install` without human review. Disabling scripts by default limits what a malicious package can do silently.

**Tradeoff:** Some legitimate packages rely on postinstall scripts for native compilation (e.g., `node-gyp` builds, `esbuild` binary downloads). These will fail silently or produce broken installs.

**Workaround:** Users can override per-install:
```bash
npm install --ignore-scripts=false <package>
```

Or set it globally inside the container session:
```bash
npm config set ignore-scripts false
```

**Rejected:** Leaving scripts enabled by default. The autonomous execution context makes the risk too high — an AI agent won't notice a supply chain attack in a postinstall script.
