#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import json, os, platform, socket, stat, psutil

COMMON_SAFE = {22, 53, 68, 80, 443, 631, 3306, 5432, 27017, 3000, 5000, 5173, 8080, 8443}

def proto_name(t):
    return "TCP" if t == socket.SOCK_STREAM else "UDP" if t == socket.SOCK_DGRAM else "?"

def tag_risk(port: int, exe: str, name: str) -> str:
    exe = exe or ""
    name = (name or "").lower()
    if port in COMMON_SAFE:
        return ""
    if any(p in exe for p in ("/tmp/", "/var/tmp/", "/dev/shm/")):
        return "suspicious_path"
    if any(x in name for x in ("vite", "node", "python", "uvicorn", "gunicorn")) and port >= 3000:
        return ""
    if port >= 49152:  # high ephemeral
        return "ephemeral"
    if port not in COMMON_SAFE and port not in range(1, 1025):
        return "uncommon_port"
    return ""

def is_world_writable(path: str) -> bool:
    try:
        st = os.stat(path)
        return bool(st.st_mode & stat.S_IWOTH)
    except Exception:
        return False

def gather_listeners():
    # Iterate processes so we can still see our own listeners without root
    rows = []
    for proc in psutil.process_iter(attrs=["pid", "name", "exe"]):
        try:
            pid = proc.info.get("pid")
            name = proc.info.get("name") or "?"
            exe  = proc.info.get("exe") or ""
            for c in proc.connections(kind="inet"):  # only this proc’s sockets
                try:
                    if c.status != psutil.CONN_LISTEN:
                        continue
                    l = c.laddr
                    port = getattr(l, "port", None)
                    proto = proto_name(c.type)
                    risk  = tag_risk(port or 0, exe, name)
                    if exe and is_world_writable(exe):
                        risk = (risk + "+ww-exe") if risk else "ww-exe"
                    rows.append({
                        "process": name, "pid": pid, "proto": proto,
                        "port": port, "exe": exe, "risk": risk
                    })
                except Exception:
                    continue
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    seen = set()
    uniq = []
    for r in rows:
        key = (r["pid"], r["proto"], r["port"], r["exe"])
        if key in seen: continue
        seen.add(key); uniq.append(r)

    uniq.sort(key=lambda r: (0 if r["proto"] == "TCP" else 1, r["port"] or 0, r["process"]))
    return uniq

def main():
    out = {"host": platform.node(), "os": platform.platform(), "listeners": gather_listeners()}
    print(json.dumps(out, ensure_ascii=False))

if __name__ == "__main__":
    main()
