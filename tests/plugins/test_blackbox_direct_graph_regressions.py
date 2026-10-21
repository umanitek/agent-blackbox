"""Behavior regressions for the bounded direct graph reader."""
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import time
import pytest
from rdflib import URIRef, Literal
from test_blackbox_direct_graph import GraphNode, CG, BASE, PART, G, DP, D, CASES, queries, compiler, rows_module, detection, config, graph_read, client_module, load_blackbox


def test_review_legacy_package_alias_keeps_blocking_parity():
    node = GraphNode()
    node.add('urn:legacy:package', 'urn:legacy', {G+'identifier': 'dep:pypi:Foo_Bar@1.0', G+'kind': 'malware', G+'severity': 'critical'})
    cfg = config.BlackboxConfig(detection_backend='dkg', context_graph_id=CG, community_graph_id='', report=False, auto_attach=False, osv_lookup=False)
    args = {'command': 'pip install foo-bar==1.0'}
    triples = [(str(s), str(p), str(o)) for s,p,o in node.store.graph(URIRef(PART))]
    oracle = compiler.build_from_rows(rows_module.rows_from_triples(PART, triples))
    expected = detection.detect_all('terminal', args, oracle, discover=False)
    assert expected and load_blackbox('guard.hooks')._would_block(replace(cfg, mode='block'), expected)
    direct = graph_read.read_for_action(cfg, 'terminal', args, client=node)
    actual = detection.detect_all('terminal', args, direct.rules, discover=False)
    assert direct.state == 'available'
    assert [x.identifier for x in actual] == [x.identifier for x in expected]


def test_review_ready_sample_advances_past_suppressed_prefix():
    node = GraphNode()
    for n in range(65):
        subject = f'urn:defender:ioc:{n:03}'
        node.add(subject, 'urn:defender:IocSignal', {DP+'iocType':'domain',DP+'value':f'{n}.evil.example'})
        if n < 64:
            node.add(f'urn:defender:correction:{n}', 'urn:defender:CorrectionSignal', {DP+'targetSubject':subject,DP+'action':'suppress'})
    cfg = config.BlackboxConfig(detection_backend='dkg', context_graph_id=CG, community_graph_id='', report=False)
    assert load_blackbox('ruleset.direct.view').lookup(cfg,'ioc:domain:64.evil.example', client=node)
    assert load_blackbox('ruleset.direct.view').ready_sample(cfg, client=node) > 0


def test_review_streamed_response_cannot_exceed_shared_deadline(tmp_path):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self,*args): pass
        def do_GET(self):
            raw = b'{"networkId":"' + b'a'*30 + b'"}'
            self.send_response(200); self.send_header('Content-Length', str(len(raw))); self.end_headers()
            try:
                for byte in raw:
                    self.wfile.write(bytes([byte])); self.wfile.flush(); time.sleep(.1)  # health: allow HX013 -- slow streaming is the deadline behavior under test
            except (BrokenPipeError, ConnectionResetError): pass
    server = ThreadingHTTPServer(('127.0.0.1',0),Handler)
    t = Thread(target=server.serve_forever,daemon=True); t.start()
    cfg = config.BlackboxConfig(dkg_url=f'http://127.0.0.1:{server.server_port}',dkg_home=str(tmp_path/'node'))
    client = client_module.LocalGraphClient(cfg,budget_s=.2)
    start=time.monotonic()
    try:
        with pytest.raises(client_module.GraphReadUnavailable): client.status()
        elapsed=time.monotonic()-start
        assert elapsed < 2.0, f'200ms deadline took {elapsed:.3f}s'
    finally:
        server.shutdown(); server.server_close(); t.join(timeout=1)


@pytest.mark.parametrize("category", ["dependency", "injection", "skill", "ioc", "fileaccess", "escalation", "unknown"])
def test_category_selection_matches_unfiltered_entities(category):
    node = GraphNode()
    for subject, kind, props, *_ in CASES:
        node.add(subject, kind, props)
    node.add('urn:legacy:ioc', 'urn:legacy', {G+'identifier':'ioc:domain:legacy.example'})
    node.add('urn:inactive:observation', 'urn:blackbox:SourceObservation',
             {queries.BP+'lifecycleStatus':'withdrawn', queries.BP+'normalizedValue':'inactive.example'})
    view = load_blackbox('ruleset.direct.view')
    # Compare evaluated RDF results, including legacy types and inactive data.
    full = node.bounded(f'SELECT DISTINCT ?threat ?category WHERE {{ {view._entities(CG)} }}', CG)
    expected = {row['threat'] for row in full['result']['bindings'] if row['category'] == Literal(category).n3()}
    scoped = node.bounded(f'SELECT DISTINCT ?threat WHERE {{ {view._entities(CG, category=category)} }}', CG)
    assert {row['threat'] for row in scoped['result']['bindings']} == expected
    # A partition probe has the same matches without manufacturing category
    # literals for Blazegraph's resolver inside a correlated EXISTS.
    probe = node.bounded(f'SELECT DISTINCT ?threat ?category WHERE {{ {queries.confirmed_scope(CG)} GRAPH ?sourceGraph {{ {view._entity_patterns(category, bind_category=False)} }} }}', CG)
    assert {row['threat'] for row in probe['result']['bindings']} == expected
    assert all('category' not in row for row in probe['result']['bindings'])


def test_ioc_partition_sampling_rechecks_owner_status_and_cross_partition_corrections():
    node = GraphNode()
    node.add('urn:dependency', 'urn:defender:DependencySignal', {DP+'package':'unrelated', DP+'ecosystem':'npm'})
    graphs = {key: BASE+'/_verifiable_memory/2/'+key for key in ('a', 'b', 'c', 'd', 'z')}
    for key, graph in graphs.items():
        node.partition(graph, 'tentative' if key == 'a' else 'confirmed')
    meta = node.store.graph(URIRef(BASE+'/_meta'))
    meta.set((URIRef(graphs['b']+'/ka'), URIRef(D+'kaUal'), URIRef('did:dkg:evm:1/0x2222222222222222222222222222222222222222/1')))
    for key in ('a', 'b', 'c', 'd'):
        node.add('urn:ioc:'+key, 'urn:defender:IocSignal', {DP+'iocType':'domain', DP+'value':key+'.example'}, graphs[key])
    node.add('urn:correction', 'urn:defender:CorrectionSignal',
             {DP+'targetSubject':'urn:ioc:c', DP+'action':'suppress'}, graphs['z'])
    cfg = config.BlackboxConfig(detection_backend='dkg', context_graph_id=CG, community_graph_id='', report=False)
    cursor = {}
    view = load_blackbox('ruleset.direct.view')
    sampled = view.sample_rules(cfg, category='ioc', client=node, cursor=cursor)
    assert set(sampled.ioc) == {'ioc:domain:d.example'}
    # A subsequent sample cannot reuse stale provenance after confirmation is lost.
    meta.set((URIRef(graphs['d']+'/ka'), URIRef(D+'status'), Literal('tentative')))
    assert not view.sample_rules(cfg, category='ioc', client=node, cursor=cursor).ioc
