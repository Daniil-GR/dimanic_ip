import unittest
from unittest.mock import patch
import web_app as w

class DnsProvisionTests(unittest.TestCase):
    def test_preview_does_not_call_mtproto(self):
        state={'phase':'done','host':'dev2.example.com','port':443,
               'scan_id':'test','rows':[{'ip':'8.8.8.8'}],'current':''}
        cfg={'mode':'production','zone':'example.com'}
        zone={'glue_type':'dns','ttl':'300','dns_sub_list':[
            {'sub_host':'dev2','record_type':'a','record_value1':'8.8.8.8'}]}
        with patch.object(w,'STATE',state), patch.object(w,'LAST',None), \
             patch.object(w,'ADD_PREVIEW',None), \
             patch.object(w.dynadot,'preview',return_value=(cfg,'dev2',zone,[])), \
             patch.object(w,'client') as client, patch.object(w,'safe_result') as check:
            r=w.dns_operation('/api/dynadot/add-preview',{'ips':'1.1.1.1,8.8.8.8'})
            self.assertEqual(r['ips'],['1.1.1.1'])
            self.assertEqual(r['duplicates'],['8.8.8.8'])
            client.assert_not_called()
            check.assert_not_called()

if __name__=='__main__':
    unittest.main()
