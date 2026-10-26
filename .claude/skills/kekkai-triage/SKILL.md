---
name: kekkai-triage
description: Investigate and explain home-network security findings from KEKKAI (結界), the Mac network monitor in kekkai/. Use when the user asks whether their network or Mac is safe, mentions a KEKKAI alert, an unknown device on the LAN, a suspicious connection or process, ARP spoofing, open ports, UPnP, or wants a security check-up or report.
---

# KEKKAI triage

KEKKAI watches this Mac's connections, the home LAN, macOS hardening settings and the home's
internet exposure. Your job is to turn its findings into a clear, calm, correct explanation and a
short list of safe actions, in Japanese unless the user writes in another language.

## Tools

Prefer the `kekkai` MCP tools when they are connected (`kekkai_status`, `kekkai_alerts`,
`kekkai_connections`, `kekkai_devices`, `kekkai_lookup_ip`, `kekkai_scan_device`, `kekkai_audit`,
`kekkai_exposure`, `kekkai_report`, `kekkai_doctor`, `kekkai_set_alert_status`).
Otherwise use the CLI from the repository root; every command has `--json`:

```sh
./kekkai/kekkai alerts --json        # open alerts
./kekkai/kekkai conns --risky --json # risky live connections
./kekkai/kekkai devices --json       # LAN devices
./kekkai/kekkai lookup <ip>          # GeoIP/ASN/threat feeds (add --external for Shodan/GreyNoise)
./kekkai/kekkai audit --json         # macOS hardening checks
./kekkai/kekkai report               # full Markdown report
./kekkai/kekkai doctor               # is KEKKAI itself working?
```

## Procedure

1. Start with `kekkai_status` (or `alerts`). If the data looks wrong or empty, run `kekkai_doctor`
   first: a broken collector is a KEKKAI bug to report, not a security finding.
2. Work from the most severe open alert down. For each, gather the evidence that would confirm or
   refute it before concluding:
   - `conn.threat_feed` / `conn.*`: look up the IP, check which process and binary path made the
     connection, and whether that binary is signed. Feed hits on CDN/shared hosting can be false
     positives; a hit plus an unsigned binary in /tmp, /Users/Shared or a hidden folder is not.
   - `lan.arp_spoof`: compare the router MAC now and before, and which LAN device shares the MAC.
     A router replacement or a new Wi-Fi extender explains it; otherwise treat it as an active
     man-in-the-middle and say so.
   - `lan.new_device`: vendor, randomized MAC (phones use these), hostname, open ports.
   - `host.persistence_new`: who installed it (recent app installs), signature, program path.
   - `exposure.*`: InternetDB data is weekly and may describe a shared IPv4 (CGNAT/DS-Lite);
     UPnP mappings show which LAN device asked the router to open a port.
3. Separate facts (from KEKKAI data) from inferences, and give a confidence (高/中/低) for every
   conclusion.
4. Recommend concrete, reversible steps with exact macOS paths (システム設定 > …). Put the urgent
   ones first (disconnect Wi-Fi, quit the process) and the follow-ups after (password changes from a
   clean device, firmware updates, router UPnP off).

## Guardrails

- Only scan devices on the user's own LAN. `kekkai_scan_device` refuses public IPs; never try to
  work around that or scan anything else.
- Do not change alert status, delete files, kill processes or edit router settings yourself;
  tell the user what to do, or do it only when they explicitly ask.
- Never claim a compromise is certain from a single signal, and never dismiss a critical alert
  without evidence that explains it.
