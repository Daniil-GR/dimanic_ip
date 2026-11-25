import unittest
from unittest.mock import patch
import dynadot_add as a

class AddTests(unittest.TestCase):
    def setUp(self):
        self.old={'glue_type':'dns','ttl':'300','dns_sub_list':[
            {'sub_host':'dev2','record_type':'a','record_value1':'8.8.8.8'},
            {'sub_host':'other','record_type':'txt','record_value1':'keep'}]}
        self.cfg={'mode':'production','zone':'example.com'}
        self.ip='1.1.1.1'

    def test_validation_and_duplicates(self):
        self.assertEqual(a.parse_ips('1.1.1.1\n1.1.1.1,8.8.8.8'),['1.1.1.1','8.8.8.8'])
        self.assertEqual(a.prepare(self.old,'dev2',[self.ip,'8.8.8.8']),([self.ip],['8.8.8.8']))
        for invalid in ('127.0.0.1','::1','300.0.0.1','224.0.0.1',''):
            with self.assertRaises(ValueError):
                a.parse_ips(invalid)

    def test_payload_is_append_only(self):
        self.assertEqual(a.payload_for(self.old,'dev2',[self.ip]),{
            'dns_sub_list':[{'sub_host':'dev2','record_type':'a','record_value1':self.ip}],
            'ttl':300,'add_dns_to_current_setting':True})

    def test_conflict_and_unknown_ttl(self):
        for zone in (dict(self.old,ttl=None),dict(self.old,dns_sub_list=[
                {'sub_host':'dev2','record_type':'cname','record_value1':'example.net'}])):
            with self.assertRaises(ValueError):
                a.payload_for(zone,'dev2',[self.ip])

    def after(self):
        return dict(self.old,dns_sub_list=self.old['dns_sub_list']+[
            {'sub_host':'dev2','record_type':'a','record_value1':self.ip,'record_value2':''}])

    def test_verify_preserves_other_records(self):
        after=self.after()
        self.assertTrue(a.verify(self.old,after,'dev2',[self.ip]))
        self.assertFalse(a.verify(self.old,dict(after,ttl='86400'),'dev2',[self.ip]))
        self.assertFalse(a.verify(self.old,dict(after,dns_sub_list=after['dns_sub_list'][1:]),'dev2',[self.ip]))

    @patch('dynadot_add.d.private_write')
    @patch('dynadot_add.d.request')
    @patch('dynadot_add.d.get_zone')
    def test_append_verified(self,get_zone,request,write):
        get_zone.side_effect=[self.old,self.after()]
        request.return_value={}
        result=a.append_records(self.cfg,'dev2',self.old,[self.ip])
        request.assert_called_once_with(self.cfg,'POST',a.payload_for(self.old,'dev2',[self.ip]))
        self.assertEqual(result['remaining'],[self.ip,'8.8.8.8'])

    @patch('dynadot_add.d.request')
    @patch('dynadot_add.d.get_zone')
    def test_changed_zone_blocks_write(self,get_zone,request):
        get_zone.return_value=dict(self.old,ttl='600')
        with self.assertRaises(ValueError):
            a.append_records(self.cfg,'dev2',self.old,[self.ip])
        request.assert_not_called()

    @patch('dynadot_add.d.private_write')
    @patch('dynadot_add.d.request')
    @patch('dynadot_add.d.get_zone')
    def test_ambiguous_post_not_repeated(self,get_zone,request,write):
        get_zone.return_value=self.old
        request.side_effect=ValueError('timeout')
        with self.assertRaises(ValueError):
            a.append_records(self.cfg,'dev2',self.old,[self.ip])
        request.assert_called_once()

if __name__=='__main__':
    unittest.main()
