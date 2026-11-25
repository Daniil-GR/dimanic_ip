import unittest
from unittest.mock import patch
import dynadot_dns as d

C={'mode':'production','key':'test-key','secret':'test-secret'}

class DynadotListTests(unittest.TestCase):
    @patch('dynadot_dns.request')
    def test_default_then_next_page(self,req):
        req.side_effect=[
            {'domain_info_list':[{'domain_name':'example.com'}],'pagination_result':{'page':1,'total':2,'has_next_page':True}},
            {'domain_info_list':[{'domain_name':'example.net'}],'pagination_result':{'page':2,'total':2,'has_next_page':False}},
        ]
        self.assertEqual(d.list_domains(C),['example.com','example.net'])
        self.assertEqual(req.call_args_list[0].kwargs['path'],'/restful/v2/domains')
        self.assertEqual(req.call_args_list[1].kwargs['path'],'/restful/v2/domains?page=2')

    @patch('dynadot_dns.request')
    def test_missing_pagination_uses_explicit_pages(self,req):
        page={'domain_info_list':[{'domain_name':'example.com'}]}
        req.side_effect=[page,page,{'domain_info_list':[]}]
        self.assertEqual(d.list_domains(C),['example.com'])
        self.assertEqual(req.call_args_list[1].kwargs['path'],'/restful/v2/domains?page=1&page_size=100')
        self.assertEqual(req.call_args_list[2].kwargs['path'],'/restful/v2/domains?page=2&page_size=100')

    @patch('dynadot_dns.request')
    def test_string_pagination(self,req):
        req.side_effect=[
            {'domain_info_list':[{'domain_name':'example.com'}],'pagination_result':{'page':'1','total':'2','has_next_page':'true'}},
            {'domain_info_list':[{'domain_name':'example.net'}],'pagination_result':{'page':'2','total':'2','has_next_page':'false'}},
        ]
        self.assertEqual(d.list_domains(C),['example.com','example.net'])

    @patch('dynadot_dns.request')
    def test_repeated_pages_fail_closed(self,req):
        req.return_value={'domain_info_list':[{'domain_name':'example.com'}]}
        with self.assertRaises(ValueError):
            d.list_domains(C)

    @patch('dynadot_dns.request')
    def test_incomplete_list_fails_closed(self,req):
        req.return_value={'domain_info_list':[{'domain_name':'example.com'}],
                          'pagination_result':{'page':1,'total':2,'has_next_page':False}}
        with self.assertRaises(ValueError):
            d.list_domains(C)

    def test_error_redacts_credentials(self):
        text=d.error_message({'message':'Bad Request','data':{'detail':'test-key test-secret example-signature'}},C,'example-signature')
        self.assertIn('Bad Request',text)
        for value in ('test-key','test-secret','example-signature'):
            self.assertNotIn(value,text)

class DynadotSignatureTests(unittest.TestCase):
    def test_documented_signature_without_request_id(self):
        headers,signature=d.signed_headers(C,'/restful/v2/domains','','')
        self.assertEqual(signature,'Ix4scQH6cnn0NN252wiBQApR+dhG1Yo25Q17r57cBYU=')
        self.assertNotIn('X-Request-ID',headers)

    def test_documented_signature_with_request_id(self):
        request_id='123e4567-e89b-12d3-a456-426614174000'
        headers,signature=d.signed_headers(C,'/restful/v2/domains','',request_id)
        self.assertEqual(signature,'A2QiImDJ+RNNAlO9btb1y4KQSz67PDkG7Hvnri/IV2w=')
        self.assertEqual(headers['X-Request-ID'],request_id)

    @patch('dynadot_dns.public_config',return_value={'configured':True})
    @patch('dynadot_dns.private_write')
    @patch('dynadot_dns.list_domains')
    def test_read_only_fallback(self,listing,write,public):
        modes=[]
        def attempt(cfg):
            modes.append(cfg['request_id_mode'])
            if len(modes)==1:
                raise d.DynadotError(400,'X-Signature provided is not valid')
            return ['example.com']
        listing.side_effect=attempt
        self.assertEqual(d.save_config(C)['domain_count'],1)
        self.assertEqual(modes,['none','uuid'])
        self.assertEqual(write.call_args.args[1]['request_id_mode'],'uuid')

class DynadotZoneTests(unittest.TestCase):
    def setUp(self):
        self.zone={'glue_type':'DNS','dns_main_list':[],
                   'dns_sub_list':[{'sub_host':'dev2','record_type':'a','record_value1':'192.0.2.10'}],
                   'ttl':'300'}

    def test_nested_uppercase(self):
        self.assertEqual(d.parse_zone({'glue_info':self.zone},'example.com'),self.zone)

    def test_flat_explicit_dns(self):
        self.assertEqual(d.parse_zone(self.zone,'example.com'),self.zone)

    def test_external_dns_rejected(self):
        with self.assertRaisesRegex(ValueError,'name_servers'):
            d.parse_zone({'glue_info':dict(self.zone,glue_type='name_servers')},'example.com')

    def test_missing_mode_rejected(self):
        data=dict(self.zone)
        del data['glue_type']
        with self.assertRaises(ValueError):
            d.parse_zone({'glue_info':data},'example.com')

    def test_diagnostic_shows_zone_not_values(self):
        with self.assertRaisesRegex(ValueError,r'example\.com') as err:
            d.parse_zone({'glue_info':{'glue_type':'unexpected-private-value'}},'example.com')
        self.assertNotIn('unexpected-private-value',str(err.exception))

    def test_zone_selection_uses_parent(self):
        self.assertEqual(d.select_zone('dev2.example.com',['example.net','example.com']),'example.com')

if __name__=='__main__':
    unittest.main()
