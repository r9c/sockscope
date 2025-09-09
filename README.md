# SockScope

A tiny **listener monitor** for your machine.  
See which processes are **listening on ports**, where their **binaries** live, whether they look **risky**, and **end** them with one click.

https://github.com/r9c/sockscope

## Why not just a port scanner?
Port scanners (like nmap) tell you what’s open *from the outside*.  
**This** runs *on your host* and shows the **process**, **PID**, **full path**, **permissions**, and simple **risk tags**:
- **ok**
- **uncommon port**
- **ephemeral**
- **suspicious path** (`/tmp`, `/dev/shm`)
- **world-writable exe**

It also has:
- **Baseline** snapshot → highlights **NEW** listeners since baseline
- **Auto-refresh** (5–60s)
- **Filters** (text, only NEW, only risky)
- **Copy path**, **End (SIGTERM)** per row
- **Translucent “glass” UI** (Tauri window transparency)

---

## Install

### Prereqs
- **Rust** (stable) + **Cargo**
- **Node 18+** / **pnpm** or **npm**
- **Python 3** (for the scanner script)
- **Tauri CLI**: `cargo install tauri-cli`

### Run dev
```bash
pnpm install   # or: npm install
pnpm tauri dev # or: npm run tauri:dev
