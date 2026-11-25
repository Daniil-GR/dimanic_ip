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
    def test_missing_pagination_fails_closed(self,req):
        req.return_value={'domain_info_list':[{'domain_name':'example.com'}]}
        with self.assertRaises(ValueError):
            d.list_domains(C)

    def test_error_redacts_credentials(self):
        text=d.error_message({'message':'Bad Request','data':{'detail':'test-key test-secret example-signature'}},C,'example-signature')
        self.assertIn('Bad Request',text)
        for value in ('test-key','test-secret','example-signature'):
            self.assertNotIn(value,text)

if __name__=='__main__':
    unittest.main()
