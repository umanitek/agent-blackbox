"""Loopback daemon responses shared by installer and plugin compatibility tests."""
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import time

@contextmanager
def replies(sequence):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def answer(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))) or b"{}")
            calls.append((self.command, self.path, body))
            data = json.dumps(sequence.pop(0) if sequence else {"state": "unexpected"}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_GET = answer
        do_POST = answer

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def completed_job():
    return {"id": "validated-job", "state": "complete", "finishedAt": time.time() * 1000,
            "capabilities": {"sourcePolicies": ["DKG_Core_chain_cache"]},
            "request": {"contextGraphId": "0x37b1Fdfd134e2b17583bCBdD3034F91504cD9C70/agent-blackbox-vm", "onChainId": "14",
                        "trustedCorePeerIds": [], "sourcePolicy": "DKG_Core_chain_cache", "mode": "core-cache"},
            "result": {"current": True, "completeAsOfSnapshot": True, "assets": 12, "committed": 12,
                       "mode": "core-cache", "sourcePolicy": "DKG_Core_chain_cache",
                       "selectedCorePeerIds": ["authenticated-core"], "sourceCore": "authenticated-core",
                       "coverageSourceCore": "authenticated-core"}}


QUERY_CAPABILITIES = {"version": 1, "chainEvidenceModes": ["rpc-only", "core-cache"]}
