"""Offline regression tests; no public network calls."""
import datetime
import json
import socket
import unittest
from unittest.mock import Mock, patch
import baseline
import security_engine as engine
from security_registry import REGISTRY
URL = 'https://example.com/'
def response(body=b'<html><script src="https://third.party/app.js"></script></html>', headers=None, status=200):
    return {'status':status, 'headers':headers or [('Content-Type','text/html')], 'body':body, 'tls':{'notAfter':'Jan  1 00:00:00 2030 GMT'}}
def grant(classes=None):
    return {'hostname':'example.com','expiresAt':(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(minutes=5)).isoformat(),'classes':classes or ['configuration','discovery','cors']}
class ScopeTests(unittest.TestCase):
    def test_apex_to_www_redirect_allowed(self):
        c=engine.Collector(lambda _:None,URL,'standard')
        responses=[response(status=302,headers=[('Location','https://www.example.com/')]),response()]
        with patch.object(c,'request',side_effect=responses) as r:
            final_url,response_,upgraded,stop=c.follow(URL)
            self.assertIsNone(stop)
            self.assertEqual(engine.urlsplit(final_url).hostname,'www.example.com')
            self.assertEqual(r.call_count,2)
    def test_scope_before_dns(self):
        c=engine.Collector(lambda _:None,URL,'standard')
        with patch.object(c,'resolve') as resolve:
            for u in ('https://example.com/admin','https://other.example.com/','https://example.com/?q=x'):
                with self.assertRaises(baseline.ScopeError): c.request(u)
            resolve.assert_not_called()
    def test_grant_validation(self):
        for change in ({'expiresAt':'2020-01-01T00:00:00Z'},{'hostname':'www.example.com'},{'classes':['injection']},{'revoked':True},{'classes':[]}):
            with self.assertRaises(baseline.ScopeError):engine.grant_valid({**grant(),**change},'example.com')
        self.assertEqual(engine.grant_valid(grant(['cors']),'example.com'),{'cors'})
    def test_expiry_after_dns(self):
        c=engine.Collector(lambda _:None,URL,'deep',grant())
        def resolve(*args):
            c.grant['revoked']=True
            return [(socket.AF_INET,('8.8.8.8',443))]
        with patch.object(c,'resolve',side_effect=resolve),patch.object(baseline,'PinnedHTTP') as transport:
            with self.assertRaises(baseline.ScopeError): c.request(URL)
            transport.assert_not_called()
    def test_request_budget_and_body_limit(self):
        c=engine.Collector(lambda _:None,URL,'standard')
        c.count=20
        with self.assertRaises(TimeoutError):c.request(URL)
        c.count=19
        wire=Mock(status=200)
        wire.getheaders.return_value=[('Content-Type','text/html')]
        wire.read1.side_effect=lambda n:b'x'*n
        connection=Mock(certificate=None)
        connection.getresponse.return_value=wire
        with patch.object(c,'resolve',return_value=[(socket.AF_INET,('8.8.8.8',443))]),patch.object(baseline,'PinnedHTTP',return_value=connection):
            self.assertEqual(len(c.request(URL)['body']),65536)
            self.assertEqual(c.count,20)
            connection.close.assert_called_once()
            self.assertNotIn('Cookie',connection.request.call_args.kwargs['headers'])
    def test_header_failure_closes(self):
        c=engine.Collector(lambda _:None,URL,'standard')
        wire=Mock(status=200)
        wire.getheaders.return_value=[('X','x'*32769)]
        connection=Mock(certificate=None)
        connection.getresponse.return_value=wire
        with patch.object(c,'resolve',return_value=[(socket.AF_INET,('8.8.8.8',443))]),patch.object(baseline,'PinnedHTTP',return_value=connection):
            with self.assertRaises(baseline.ScopeError):c.request(URL)
            connection.close.assert_called_once()
    def test_owned_loopback_transport(self):
        # Fixed synthetic fixture only. URL hostname is retained for Host; socket
        # destination is patched to the fixture, with no public DNS or connection.
        with baseline.lab_fixture() as port:
            c=engine.Collector(lambda _:None,'http://example.com/','standard')
            with patch.object(c,'resolve',return_value=[(socket.AF_INET,('127.0.0.1',port))]):
                result=c.request('http://example.com/')
            self.assertEqual(result['status'],200)
            self.assertIn(b'ShipSafe synthetic fixture',result['body'])
            self.assertEqual(c.count,1)
    def test_origin_probe_requires_cors_grant(self):
        for mode,auth in [('standard',None),('deep',grant(['configuration']))]:
            c=engine.Collector(lambda _:None,URL,mode,auth)
            with patch.object(c,'resolve') as resolve:
                with self.assertRaises(baseline.ScopeError):c.request(URL,origin=True)
                resolve.assert_not_called()
    def test_action_redirect_is_not_requested(self):
        c=engine.Collector(lambda _:None,URL,'standard')
        with patch.object(c,'request',return_value=response(status=302,headers=[('Location','/%6cogout')])) as r:
            self.assertEqual(c.follow(URL)[3],'REDIRECT_PATH')
            self.assertEqual(r.call_count,1)
class ReportTests(unittest.TestCase):
    def run_report(self,mode='standard',config=None,initial=None,events=None):
        requests=[]
        def request(c,url,origin=False):
            requests.append((url,origin));c.count+=1
            if url.endswith('/.git/HEAD'):return response(b'ref: refs/heads/main\n')
            if url.endswith(engine.SAFE_METADATA):return response(b'Contact: mailto:security@example.com')
            return initial or response()
        with patch.object(engine.Collector,'request',new=request), patch.object(engine, 'observe_dns', return_value={}):
            report=engine.run(config or {'mode':mode,'url':URL,**({'authorization':grant()} if mode=='deep' else {})},events.append if events is not None else lambda _:None)
        return report,requests
    def test_standard_emits_ordered_check_lifecycle_events_for_active_observations(self):
        events=[]
        report,_=self.run_report(events=events)
        starts=[event for event in events if event.get('stage')=='check']
        done=[event for event in events if event.get('stage')=='check_done']
        self.assertEqual([event['checkId'] for event in starts],[event['checkId'] for event in done])
        self.assertEqual(len(starts),len(set(event['checkId'] for event in starts)))
        self.assertEqual(set(event['checkId'] for event in starts),{result['id'] for result in report['manifest']['unifiedResults'] if result['id'] in engine.IMPLEMENTED and not result['id'].startswith('deep-') and not result['id'].startswith('dns-')})
        for start,finish in zip(starts,done):
            self.assertEqual(start['timestamp'].__class__,str)
            self.assertIn(finish['status'],('passed','observation','skipped'))
            self.assertIn(' — ',finish['message'])
    def test_selected_deep_check_classes_emit_lifecycle_events(self):
        events=[]
        self.run_report('deep',events=events)
        lifecycle={(event['stage'],event.get('checkId')) for event in events}
        self.assertTrue({('check','deep-git-head'),('check_done','deep-git-head'),('check','deep-discovery'),('check_done','deep-discovery'),('check','deep-cors'),('check_done','deep-cors')}.issubset(lifecycle))
    def test_standard_does_not_claim_exploits_or_contact_scripts(self):
        report,requests=self.run_report()
        results={r['id']:r for r in report['manifest']['unifiedResults']}
        for id_ in ('injection','api','authentication','jwt','csrf','graphql','deep-zap','deep-nuclei','deep-git-head'):
            self.assertEqual(results[id_]['status'],'NOT_TESTED')
            self.assertNotIn(id_,[f['checkId'] for f in report['findings']])
        self.assertTrue(all(engine.urlsplit(u).hostname=='example.com' for u,_ in requests))
        self.assertFalse(any(origin for _,origin in requests))
        self.assertNotIn('third.party',json.dumps(report))
    def test_deep_discovery_bounds_and_classes(self):
        body=b'<html>'+b''.join(('<a href="/page'+str(i)+'">link</a>').encode() for i in range(8))+b'<a href="/logout">out</a>'
        report,requests=self.run_report('deep',initial=response(body))
        self.assertLessEqual(len([u for u,_ in requests if '/page' in u]),3)
        self.assertTrue(any(u.endswith('/.git/HEAD') for u,_ in requests))
        self.assertEqual(sum(origin for _,origin in requests),1)
        self.assertNotIn('refs/heads/main',json.dumps(report))
    def test_ungranted_classes_not_requested(self):
        _,requests=self.run_report('deep',{'mode':'deep','url':URL,'authorization':grant(['cors'])})
        self.assertFalse(any(u.endswith('/.git/HEAD') for u,_ in requests))
    def test_absent_cookies_are_not_applicable(self):
        report,_=self.run_report()
        for r in report['manifest']['unifiedResults']:
            if r['id'].startswith('cookie-'): self.assertEqual(r['status'],'NOT_APPLICABLE')
    def test_no_guessed_source_map_paths(self):
        _,requests=self.run_report()
        self.assertFalse(any(u.endswith('.map') for u,_ in requests))
        _,requests=self.run_report(initial=response(b'<html><!--# sourceMappingURL=/app.js.map -->'))
        self.assertTrue(any(u.endswith('/app.js.map') for u,_ in requests))
    def test_cross_host_source_map_not_requested(self):
        _,requests=self.run_report(initial=response(b'<html><!--# sourceMappingURL=https://other.com/app.js.map -->'))
        self.assertFalse(any(engine.urlsplit(u).hostname!='example.com' for u,_ in requests))
    def test_partial_withholds_score(self):
        report,requests=self.run_report(initial=response(status=302,headers=[('Location','https://www.other.com/')]))
        self.assertEqual(len(requests),1)
        self.assertTrue(report['manifest']['scopeLimited'])
        self.assertIsNone(report['manifest']['posture']['value'])
    def test_cookie_values_redacted(self):
        extra,_=engine.extra_observations(URL,response(headers=[('Set-Cookie','__Host-session=SECRET; SameSite=None; Domain=example.com; Path=/private')]))
        self.assertEqual(extra['cookie-samesite-valid'][0],'WARNING')
        self.assertEqual(extra['cookie-prefix'][0],'WARNING')
        self.assertNotIn('SECRET',json.dumps(extra))
    def test_narrow_cookie_path_and_short_expiry_are_not_penalized(self):
        expiry=(datetime.datetime.now(datetime.timezone.utc)+datetime.timedelta(days=2)).strftime('%a, %d %b %Y %H:%M:%S GMT')
        extra,_=engine.extra_observations(URL,response(headers=[('Set-Cookie','session=SECRET; Path=/account; SameSite=Lax; Expires='+expiry)]))
        self.assertEqual(extra['cookie-path'][0],'PASS')
        self.assertEqual(extra['cookie-lifetime'][0],'PASS')
        extra,_=engine.extra_observations(URL,response(b'<link rel="canonical" href="http://example.com/">',headers=[('Content-Type','text/html')]))
        self.assertEqual(extra['mixed-content'][0],'PASS')
    def test_encoded_bodies_do_not_earn_analysis_credit(self):
        report,_=self.run_report("deep", initial=response(b'compressed-data',headers=[('Content-Type','text/html'),('Content-Encoding','gzip')]))
        outcomes={r['id']:r['status'] for r in report['manifest']['unifiedResults']}
        for id_ in ('error-disclosure','mixed-content','script-inventory','library-inventory','source-map','deep-discovery'):
            self.assertEqual(outcomes[id_],'NOT_TESTED')
    def test_registry_json_matches_definitions(self):
        from pathlib import Path
        self.assertEqual(REGISTRY,json.loads(Path(__file__).with_name("security_registry.json").read_text()))
    def test_registry_complete(self):
        self.assertEqual(len(REGISTRY),len({d['id'] for d in REGISTRY}))
        for d in REGISTRY:self.assertTrue({'id','category','authorization','scope','methods','paths','budgets','evidence','severity','confidence','version'}.issubset(d))
    def test_untested_never_earns_credit(self):
        report,_=self.run_report('deep',{'mode':'deep','url':URL,'authorization':grant(['cors'])})
        p=report['manifest']['posture']
        self.assertEqual(p['value'],round(100*p['passed']/p['eligible']))
        self.assertEqual(p['untestedCredit'],0)
        self.assertGreater(p['eligible'],p['tested'])
if __name__=='__main__':unittest.main()
