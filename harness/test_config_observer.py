"""Offline observer tests; no server, dependencies, secrets or OAuth cases."""
import json
import unittest
from config_observer import observe

RESOURCES=[('application','/api/application/synthetic-app','application','synthetic-app'),
           ('tenant','/api/tenant/synthetic-tenant','tenant','synthetic-tenant')]
class Response:
    def __init__(self,status,body=None,content=b''):
        self.status_code,self.body,self.content=status,body,content
    def json(self):
        if self.body is None: raise ValueError()
        return self.body
class Session:
    def __init__(self,responses): self.responses=iter(responses);self.paths=[]
    def get(self,path): self.paths.append(path);return next(self.responses)
def ok():return [Response(200,{'application':{'id':'synthetic-app'}}),Response(200,{'tenant':{'id':'synthetic-tenant'}})]
class Tests(unittest.TestCase):
    def test_success(self):
        records=[];session=Session(ok());self.assertIsNotNone(observe(session,'http://127.0.0.1:9011',RESOURCES,records))
        self.assertTrue(all(x['expected_id_matches'] for x in records));self.assertEqual(len(session.paths),2)
    def test_auth_denial_not_retried(self):
        records=[];session=Session([Response(401),ok()[1]])
        self.assertIsNone(observe(session,'',RESOURCES,records,sleep=lambda _:self.fail('retry')))
        self.assertEqual(records[0]['category'],'AUTHENTICATION_OR_SCOPE_DENIED')
    def test_readiness_only(self):
        records=[];waits=[];session=Session([Response(404),Response(503)]+ok())
        self.assertIsNotNone(observe(session,'',RESOURCES,records,sleep=waits.append));self.assertEqual(waits,[2])
    def test_bounded_absence(self):
        records=[];self.assertIsNone(observe(Session([Response(404)]*10),'',RESOURCES,records,sleep=lambda _:None));self.assertEqual(len(records),10)
    def test_no_response_values_leak(self):
        records=[];marker='DO_NOT_PUBLISH_SYNTHETIC_MARKER'
        observe(Session([Response(400,{'fieldErrors':{marker:marker},'secret':marker}),Response(500,content=marker.encode())]),'',RESOURCES,records)
        self.assertNotIn(marker,json.dumps(records));self.assertEqual(records[1]['body'],'NON_JSON')
    def test_transport_failure(self):
        records=[];self.assertIsNone(observe(Session([]),'',RESOURCES,records));self.assertEqual(records[0]['category'],'TRANSPORT_ERROR')
if __name__=='__main__':unittest.main()
