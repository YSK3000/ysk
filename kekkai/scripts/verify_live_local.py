#!/usr/bin/env python3
"""Verify real OS socket collection -> monitor -> authenticated HTTP, without LAN scans or cloud calls."""
import copy
import http.client
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))


def main():
    with tempfile.TemporaryDirectory(prefix="kekkai-live-check-") as work:
        os.environ["KEKKAI_HOME"] = work
        from kekkai import config, server
        from kekkai.monitor import Monitor
        from kekkai.store import Store
        cfg = config.Config(copy.deepcopy(config.DEFAULTS), "unused")
        cfg.set("notify.macos", False)
        cfg.set("privacy.external_lookups", False)
        cfg.set("ai.provider", "off")
        cfg.set("monitor.interval_sec", 1)
        monitor = Monitor(cfg, Store(str(Path(work) / "check.db")))
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        client = socket.create_connection(("127.0.0.1", port), timeout=3)
        peer, _ = listener.accept()
        api = server.Server(("127.0.0.1", 0), server.App(monitor, cfg, "v" * 43))
        api_thread = threading.Thread(target=api.serve_forever, daemon=True)
        worker = threading.Thread(target=monitor._loop, args=("fast", monitor.fast_cycle, lambda: 1, 0), daemon=True)
        monitor._threads.append(worker)
        api_thread.start()
        worker.start()
        def request(path):
            conn = http.client.HTTPConnection("127.0.0.1", api.server_address[1], timeout=5)
            try:
                conn.request("GET", path, headers={"Authorization": "Bearer " + "v" * 43})
                response = conn.getresponse()
                assert response.status == 200, path
                return json.loads(response.read())
            finally:
                conn.close()
        try:
            deadline = time.monotonic() + 40
            while monitor.state["cycle"] < 2 and time.monotonic() < deadline:
                time.sleep(0.1)
            summary = request("/api/summary")
            rows = request("/api/connections")["connections"]
            found = [r for r in rows if r["raddr"] == "127.0.0.1" and r["rport"] == port and r["state"] == "ESTABLISHED"]
            assert summary["cycle"] >= 2, "collection did not repeat"
            assert summary["monitoring"]["status"] in ("live", "offline"), summary["monitoring"]["label"]
            assert found, "real loopback connection was not collected"
            own_pids = {os.getpid()}
            if sys.platform.startswith("linux"):
                # procfs may be mounted from an outer PID namespace (e.g. CI containers).
                for line in Path("/proc/self/status").read_text().splitlines():
                    if line.startswith("Pid:"):
                        own_pids.add(int(line.split()[1]))
            assert any(r["pid"] in own_pids for r in found), "current process PID was not associated"
            assert len(request("/api/coverage")["cards"]) == 5
            print("PASS real OS connection -> PID -> repeated collection -> authenticated HTTP")
            print("platform=%s cycles=%s status=%s (no addresses or tokens printed)" % (
                summary["platform"], summary["cycle"], summary["monitoring"]["status"]))
        finally:
            client.close()
            peer.close()
            listener.close()
            monitor.stop()
            api.shutdown()
            api.server_close()
            api_thread.join(timeout=2)
            if not worker.is_alive():
                monitor.store.close()


if __name__ == "__main__":
    main()
