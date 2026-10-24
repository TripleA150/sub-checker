#!/usr/bin/env python3
"""Xray subscription checker.

Reads files whose lines are subscription URLs or individual keys, keeps only keys
secured by tls/reality (or security=none with a real encryption method set),
tests each one through Xray-core several times and writes the working keys out,
plus the subset whose servers are on the Russian whitelist (openlibrecommunity/rewl).
"""
import argparse
import base64
import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import parse_qs, unquote, urlsplit

SCHEMES = ("vless://", "vmess://", "trojan://")
NO_ENCRYPTION = ("", "none", "zero")
REWL = "https://raw.githubusercontent.com/openlibrecommunity/rewl/refs/heads/master/data/pub/"


def b64(s):
    s = s.strip().replace("+", "-").replace("/", "_")
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)).decode()


def extract(text):
    """Return the keys found in a subscription body (plain or base64)."""
    if not any(s in text for s in SCHEMES):
        try:
            text = b64("".join(text.split()))
        except Exception:
            return []
    return [l.strip() for l in text.splitlines() if l.strip().startswith(SCHEMES)]


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "sub-checker"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode("utf-8", "replace")


def stream(q, address):
    net, sec = q.get("type", "tcp"), q["security"]
    s = {"network": net, "security": sec}
    tls = {"serverName": q.get("sni") or q.get("host", "").split(",")[0] or address}
    if sec == "tls":
        if "fp" in q:
            tls["fingerprint"] = q["fp"]
        if "alpn" in q:
            tls["alpn"] = q["alpn"].split(",")
        s["tlsSettings"] = tls
    elif sec == "reality":
        s["realitySettings"] = {**tls, "fingerprint": q.get("fp", "chrome"), "publicKey": q.get("pbk", ""),
                                "shortId": q.get("sid", ""), "spiderX": q.get("spx", ""),
                                "mldsa65Verify": q.get("pqv", "")}
    # shortcut: kcp/quic headers and seeds are not mapped, add them if such keys show up
    t = {k: q[k] for k in ("path", "host", "serviceName", "mode") if k in q}
    if net == "grpc":
        t["multiMode"] = t.pop("mode", "") == "multi"
    if net == "xhttp" and q.get("extra", "null") != "null":
        t["extra"] = json.loads(q["extra"])
    if net in ("tcp", "raw") and q.get("headerType") == "http":
        t = {"header": {"type": "http", "request": {"path": [q.get("path", "/")],
                                                   "headers": {"Host": q.get("host", "").split(",")}}}}
    s[net + "Settings"] = t
    return s


def parse(link):
    """Return an Xray outbound for the key, or None if it is malformed or not encrypted."""
    try:
        scheme = link.split("://", 1)[0]
        if scheme == "vmess":
            j = json.loads(b64(link[8:].split("#")[0]))
            q = {"type": j.get("net"), "security": j.get("tls"), "sni": j.get("sni"), "host": j.get("host"),
                 "path": j.get("path"), "fp": j.get("fp"), "alpn": j.get("alpn"), "headerType": j.get("type"),
                 "encryption": j.get("scy")}
            if q["type"] == "grpc":
                q["serviceName"] = q.pop("path")
            q = {k: str(v) for k, v in q.items() if v}
            address, port = j["add"], int(j["port"])
            settings = {"vnext": [{"address": address, "port": port, "users": [
                {"id": j["id"], "alterId": int(j.get("aid") or 0), "security": q.get("encryption", "auto")}]}]}
        else:
            u = urlsplit(link)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}
            address, port = u.hostname, u.port
            if scheme == "trojan":
                settings = {"servers": [{"address": address, "port": port, "password": unquote(u.username)}]}
            elif scheme == "vless":
                settings = {"vnext": [{"address": address, "port": port, "users": [
                    {"id": unquote(u.username), "encryption": q.get("encryption", "none"), "flow": q.get("flow", "")}]}]}
            else:
                return None
        # a key must state its security; a missing value is not read as "none" or "tls"
        if q.get("security") not in ("tls", "reality"):
            # trojan has no encryption of its own, so without tls it is plaintext
            if q.get("security") != "none" or scheme == "trojan" or q.get("encryption", "") in NO_ENCRYPTION:
                return None
        if not address or not port:
            return None
        return {"protocol": scheme, "settings": settings,
                "streamSettings": stream(q, address)}
    except Exception:
        return None


def endpoint(outbound):
    s = (outbound["settings"].get("vnext") or outbound["settings"]["servers"])[0]
    return s["address"], s["port"]


def reachable(host, port, attempts):
    """Cheap pre-check: TCP connect to the port, else ICMP ping (covers UDP-only servers like kcp/h3)."""
    for _ in range(attempts):
        try:
            socket.create_connection((host, port), timeout=3).close()
            return True
        except OSError:
            pass
    try:  # ping exits 0 if any of the probes got an answer
        return subprocess.run(["ping", "-c", str(attempts), "-W", "2", host], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=attempts * 3 + 5).returncode == 0
    except (OSError, subprocess.TimeoutExpired):  # no ping binary or it hung
        return False


def load_whitelist(report, verified):
    """Subnets from ru.report.yaml and single IPs from ru.verified.yaml."""
    # shortcut: regex instead of a YAML parser (stdlib only), fine while the files stay machine-generated
    return ([ipaddress.ip_network(c, strict=False) for c in re.findall(r"cidr:\s*(\S+)", report)],
            {ipaddress.ip_address(i) for i in re.findall(r"-\s*ip:\s*(\S+)", verified)})


def whitelisted(host, nets, ips):
    """Report subnets first; if none match, the detailed per-IP verified list."""
    try:
        addrs = {ipaddress.ip_address(i[4][0]) for i in socket.getaddrinfo(host, None)}
    except (OSError, ValueError):  # unresolvable host
        return False
    return any(addr in net for addr in addrs for net in nets) or bool(addrs & ips)


def check(outbound, port, a):
    """True if a request through the key succeeds in any of a.attempts tries."""
    cfg = {"log": {"loglevel": "none"},
           "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks"}],
           "outbounds": [outbound]}
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(cfg, f)
    p = subprocess.Popen([a.xray, "run", "-c", f.name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(50):  # wait up to 5s for the inbound to listen
            if p.poll() is not None:  # xray rejected the config
                return False
            with socket.socket() as s:
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    break
            time.sleep(0.1)
        for _ in range(a.attempts):
            r = subprocess.run(["curl", "-so", os.devnull, "-w", "%{http_code}", "-m", str(a.timeout),
                                "-x", f"socks5h://127.0.0.1:{port}", a.url], capture_output=True, text=True)
            if r.stdout.startswith("2"):
                return True
        return False
    finally:
        p.kill()
        p.wait()
        os.unlink(f.name)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("inputs", nargs="+", help="files with subscription URLs and/or keys, one per line")
    ap.add_argument("-o", "--output", default="valid.txt")
    ap.add_argument("--xray", default="xray", help="path to the xray binary")
    ap.add_argument("--attempts", type=int, default=3, help="tries per key; one success is enough")
    ap.add_argument("--timeout", type=int, default=10, help="seconds per try")
    ap.add_argument("--workers", type=int, default=32)
    ap.add_argument("--url", default="https://www.gstatic.com/generate_204")
    ap.add_argument("--wl-output", default="valid_wl.txt", help="working keys on whitelisted servers")
    a = ap.parse_args()

    links = []
    for path in a.inputs:
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.startswith(("http://", "https://")):
                    try:
                        links += extract(fetch(line))
                    except Exception as e:
                        print(f"skip {line}: {e}", file=sys.stderr)
                else:
                    links += extract(line)

    uniq = {}  # same outbound with a different name or param order is the same key
    for link in links:
        ob = parse(link)
        if ob:
            uniq.setdefault(json.dumps(ob, sort_keys=True), (link, ob))
    items = list(uniq.values())
    print(f"{len(links)} keys found, {len(items)} unique encrypted keys", file=sys.stderr)

    endpoints = sorted({endpoint(ob) for _, ob in items})
    with ThreadPoolExecutor(a.workers * 4) as ex:  # sockets and ping are cheap next to xray processes
        up = {e for e, ok in zip(endpoints, ex.map(lambda e: reachable(*e, a.attempts), endpoints)) if ok}
    items = [(link, ob) for link, ob in items if endpoint(ob) in up]
    print(f"{len(up)}/{len(endpoints)} servers answer TCP/ICMP, {len(items)} keys go to the Xray test", file=sys.stderr)

    with ThreadPoolExecutor(a.workers) as ex:
        results = list(ex.map(lambda i: check(items[i][1], 20000 + i % 40000, a), range(len(items))))
    valid = [(link, ob) for (link, ob), ok in zip(items, results) if ok]
    print(f"{len(valid)} keys work", file=sys.stderr)
    if not valid:  # most likely a network outage on our side; keep the previous file
        return 1
    with open(a.output, "w", encoding="utf-8") as f:
        f.write("".join(link + "\n" for link, _ in valid))

    try:
        nets, ips = load_whitelist(fetch(REWL + "ru.report.yaml"), fetch(REWL + "ru.verified.yaml"))
    except Exception as e:  # keep the previous valid_wl.txt rather than emptying it
        print(f"whitelist check skipped: {e}", file=sys.stderr)
        return 0
    with ThreadPoolExecutor(a.workers) as ex:  # DNS lookups
        on_wl = list(ex.map(lambda item: whitelisted(endpoint(item[1])[0], nets, ips), valid))
    wl = [link for (link, _), ok in zip(valid, on_wl) if ok]
    print(f"{len(wl)} working keys are on whitelisted servers", file=sys.stderr)
    with open(a.wl_output, "w", encoding="utf-8") as f:
        f.write("".join(link + "\n" for link in wl))
    return 0


if __name__ == "__main__":
    sys.exit(main())
