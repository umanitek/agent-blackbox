"""Exercise cold/warm/evicted model states over real bounded local HTTP."""
import json
import time
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from _blackbox_loader import load_blackbox
from test_blackbox_semantic import fixture, TEXT

semantic = load_blackbox('semantic')
readiness = load_blackbox('semantic.readiness')


def test_live_residency_warmup_eviction_and_digest_change(tmp_path):
    state = {'embedding': False, 'review': False, 'digest': 'a' * 64, 'loaded_digest': 'a' * 64, 'calls': []}
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def reply(self, value):
            raw = json.dumps(value).encode(); self.send_response(200)
            self.send_header('Content-Length', str(len(raw))); self.end_headers(); self.wfile.write(raw)
        def do_GET(self):
            model = {'name': 'local-test:latest', 'digest': state['digest']}
            if self.path == '/api/ps':
                self.reply({'models': [{**model, 'digest': state['loaded_digest'], 'context_length': 8192}] if state['review'] else []})
            else: self.reply({'models': [model]})
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
            state['calls'].append((self.path, body))
            if self.path == '/api/entities/readiness':
                if body['warmup']: state['embedding'] = True
                self.reply({'version': 1, 'contextGraphId': body['contextGraphId'], 'indexId': body['indexId'],
                    'view': 'verifiable-memory', 'coverage': 'local-indexed-subset', 'modelFingerprint': 'nomic@digest',
                    'ready': state['embedding'], 'observedAt': '2026-10-10T00:00:00Z'})
            else:
                state['review'] = True
                self.reply({'message': {'content': json.dumps({'is_threat': False, 'context': 'ordinary'})}})
    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True); thread.start()
    cfg, _ = fixture(); url = f'http://127.0.0.1:{server.server_port}'
    cfg = replace(cfg, dkg_url=url, dkg_home=str(tmp_path), semantic=replace(cfg.semantic, model_url=url))
    try:
        assert semantic.assess(cfg, TEXT, 'in-tool-output').code == 'SEMANTIC_MODEL_NOT_READY'
        assert not any(path == '/api/chat' for path, _ in state['calls'])
        result = semantic.prepare(cfg)
        assert result['state'] == 'ready' and result['preparation_seconds'] >= 0
        chat = next(body for path, body in state['calls'] if path == '/api/chat')
        assert chat['options']['num_ctx'] == 8192 and TEXT not in json.dumps(chat)
        assert readiness.check(cfg, time.monotonic() + 2)['digest'] == 'a' * 64
        state['review'] = False
        assert semantic.assess(cfg, TEXT, 'in-tool-output').code == 'SEMANTIC_MODEL_NOT_READY'
        state['review'] = True; state['digest'] = 'b' * 64
        assert semantic.assess(cfg, TEXT, 'in-tool-output').code == 'SEMANTIC_MODEL_NOT_READY'
        state['digest'] = 'a' * 64
        with readiness.model_lane():
            assert semantic.prepare(cfg)['code'] == 'SEMANTIC_REVIEW_BUSY'
        assert semantic.prepare(cfg)['state'] == 'ready'  # Admission released after refusal.
    finally:
        server.shutdown(); server.server_close(); thread.join(2)


def test_startup_preparation_uses_owning_profile_a_b_a(tmp_path, monkeypatch):
    from hermes_constants import set_hermes_home_override, reset_hermes_home_override, get_hermes_home
    from agent import memory_provider
    worker = load_blackbox('guard.semantic_review'); hooks = load_blackbox('guard.hooks')
    cfg, _ = fixture(); observed = []; threads = []
    monkeypatch.setattr(hooks, '_config', lambda: cfg)
    monkeypatch.setattr(hooks.background, '_spawn_auto_attach', lambda _: None)
    monkeypatch.setattr(worker.semantic, 'prepare', lambda _: observed.append(str(get_hermes_home())) or {'state': 'ready'})
    monkeypatch.setattr(worker.audit, 'record', lambda **_: None)
    factory = memory_provider.spawn_context_thread
    def tracked(*args, **kwargs):
        thread = factory(*args, **kwargs); threads.append(thread); return thread
    monkeypatch.setattr(memory_provider, 'spawn_context_thread', tracked)
    for name in ('A', 'B', 'A'):
        home = tmp_path / name; home.mkdir(exist_ok=True)
        token = set_hermes_home_override(str(home))
        try:
            hooks.on_session_start('test'); threads[-1].join(3)
            assert not threads[-1].is_alive()
        finally: reset_hermes_home_override(token)
    assert observed == [str(tmp_path / name) for name in ('A', 'B', 'A')]
