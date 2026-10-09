import unittest
from unittest.mock import patch, MagicMock
from soc_email_analyzer.analyzer.spf_investigator import SpfInvestigator
import dns.resolver

class TestSpfInvestigator(unittest.TestCase):
    def setUp(self):
        self.investigator = SpfInvestigator()

    def _mock_dns_response(self, record_type, records):
        # Create a mock answer that acts like dnspython's answer object
        mock_answer = []
        for r in records:
            mock_data = MagicMock()
            if record_type == 'TXT':
                mock_data.strings = [r.encode('utf-8')]
            elif record_type in ['A', 'AAAA']:
                mock_data.address = r
            elif record_type == 'MX':
                mock_data.exchange.to_text.return_value = r
            mock_answer.append(mock_data)
        return mock_answer

    @patch('dns.resolver.Resolver.resolve')
    def test_spf_pass_ip4(self, mock_resolve):
        def side_effect(domain, rdtype):
            if domain == 'example.com' and rdtype == 'TXT':
                return self._mock_dns_response('TXT', ['v=spf1 ip4:192.168.1.0/24 -all'])
            raise dns.resolver.NXDOMAIN()

        mock_resolve.side_effect = side_effect

        res, exp, _, trace = self.investigator._evaluate_spf('example.com', '192.168.1.50')
        self.assertEqual(res, 'pass')
        self.assertIn('Matched IP network', exp)

    @patch('dns.resolver.Resolver.resolve')
    def test_spf_fail_all(self, mock_resolve):
        def side_effect(domain, rdtype):
            if domain == 'example.com' and rdtype == 'TXT':
                return self._mock_dns_response('TXT', ['v=spf1 -all'])
            raise dns.resolver.NXDOMAIN()

        mock_resolve.side_effect = side_effect

        res, exp, _, trace = self.investigator._evaluate_spf('example.com', '1.2.3.4')
        self.assertEqual(res, 'fail')
        self.assertEqual(trace[-1]['mechanism'], '-all')

    @patch('dns.resolver.Resolver.resolve')
    def test_spf_nested_include_and_redirect(self, mock_resolve):
        def side_effect(domain, rdtype):
            if domain == 'start.com' and rdtype == 'TXT':
                return self._mock_dns_response('TXT', ['v=spf1 include:middle.com -all'])
            if domain == 'middle.com' and rdtype == 'TXT':
                return self._mock_dns_response('TXT', ['v=spf1 redirect=end.com'])
            if domain == 'end.com' and rdtype == 'TXT':
                return self._mock_dns_response('TXT', ['v=spf1 ip4:10.0.0.1 ~all'])
            raise dns.resolver.NXDOMAIN()

        mock_resolve.side_effect = side_effect

        # Test passing IP
        res, exp, _, trace = self.investigator._evaluate_spf('start.com', '10.0.0.1')
        self.assertEqual(res, 'pass')

        # Test failing IP (hits ~all in end.com, but since it's an include, include returns softfail,
        # so evaluating start.com continues and hits -all)
        res, exp, _, trace = self.investigator._evaluate_spf('start.com', '10.0.0.2')
        self.assertEqual(res, 'fail')

    @patch('dns.resolver.Resolver.resolve')
    def test_spf_lookup_limit(self, mock_resolve):
        def side_effect(domain, rdtype):
            if rdtype == 'TXT':
                # Create an infinite loop of includes
                return self._mock_dns_response('TXT', [f'v=spf1 include:loop.com -all'])
            raise dns.resolver.NXDOMAIN()

        mock_resolve.side_effect = side_effect

        res, exp, count, trace = self.investigator._evaluate_spf('loop.com', '1.1.1.1')
        self.assertEqual(res, 'permerror')
        self.assertIn('limit exceeded', exp)
        self.assertGreater(count, 10)

    def test_extract_ip(self):
        headers = [
            "from internal.net (internal.net [10.0.0.5]) by mail.company.com",
            "from mail.sender.com (mail.sender.com [203.0.113.50]) by mx.company.com"
        ]
        ip, _ = self.investigator._extract_ip_from_received(headers)
        self.assertEqual(ip, '203.0.113.50')

    def test_alignment(self):
        self.assertTrue(self.investigator._check_alignment('chase.com', 'bounce.chase.com', strict=False))
        self.assertFalse(self.investigator._check_alignment('chase.com', 'bounce.chase.com', strict=True))
        self.assertFalse(self.investigator._check_alignment('chase.com', 'goia.io', strict=False))

if __name__ == '__main__':
    unittest.main()
