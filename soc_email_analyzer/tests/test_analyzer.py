import unittest
import os
from soc_email_analyzer.analyzer.parser import EmailParser
from soc_email_analyzer.analyzer.scoring import ScoreEngine

class TestAnalyzer(unittest.TestCase):
    def setUp(self):
        self.parser = EmailParser()
        self.sample_dir = os.path.join(os.path.dirname(__file__), '..', 'samples')

        # Ensure sample dir exists
        os.makedirs(self.sample_dir, exist_ok=True)

        # Create a mock benign eml
        self.benign_eml_path = os.path.join(self.sample_dir, 'benign.eml')
        with open(self.benign_eml_path, 'w') as f:
            f.write("""Received: from mail.example.com (mail.example.com [192.168.1.1])
	by mx.company.com (Postfix) with ESMTPS id 12345
	for <user@company.com>; Wed,  9 Oct 2024 10:00:00 +0000 (UTC)
From: trusted@example.com
To: user@company.com
Subject: Weekly Report
Date: Wed, 9 Oct 2024 10:00:00 +0000
Message-ID: <12345@example.com>
Authentication-Results: mx.company.com; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain

Here is the weekly report you requested.
Please review it when you have time.
""")

        # Create a mock malicious eml
        self.malicious_eml_path = os.path.join(self.sample_dir, 'malicious.eml')
        with open(self.malicious_eml_path, 'w') as f:
            f.write("""From: admin@paypal-secure-update.com
Reply-To: attacker@hacker.net
To: victim@company.com
Subject: URGENT: Account Suspension
Date: Wed, 9 Oct 2024 10:00:00 +0000
Message-ID: <666@attacker.net>
Authentication-Results: mx.company.com; spf=fail; dkim=fail; dmarc=fail
Content-Type: text/html

<html>
<body>
    <p>URGENT action required!</p>
    <p>Please <a href="http://192.168.1.100/login">login to confirm</a> your credentials immediately or your account will be suspended within 24 hours.</p>
</body>
</html>
""")

    def tearDown(self):
        # Clean up files
        if os.path.exists(self.benign_eml_path):
            os.remove(self.benign_eml_path)
        if os.path.exists(self.malicious_eml_path):
            os.remove(self.malicious_eml_path)

    def test_benign_email(self):
        results = self.parser.parse_file(self.benign_eml_path)
        self.assertEqual(results['severity'], 'Informational')
        self.assertEqual(results['score'], 0)
        self.assertEqual(results['auth']['spf'], 'pass')

    def test_malicious_email(self):
        results = self.parser.parse_file(self.malicious_eml_path)
        self.assertGreater(results['score'], 50)
        self.assertIn(results['severity'], ['High', 'Critical'])

        # Check specific findings
        categories = [f['category'] for f in results['findings']]
        self.assertIn('Authentication Failure', categories)
        self.assertIn('Header Anomaly', categories) # Reply-to mismatch
        self.assertIn('Social Engineering', categories) # Urgency/credentials
        self.assertIn('Suspicious URL', categories) # IP address

    def test_scoring_engine(self):
        engine = ScoreEngine()
        findings = [
            {'severity': 'High', 'category': 'A'},
            {'severity': 'High', 'category': 'A'}, # Diminishing returns (50%)
            {'severity': 'Medium', 'category': 'B'},
            {'severity': 'Low', 'category': 'C'}
        ]
        score, severity, exp = engine.calculate(findings)
        # Expected score: 25 + 12 (half of 25) + 10 + 5 = 52
        self.assertEqual(score, 52)
        self.assertEqual(severity, 'Medium')

if __name__ == '__main__':
    unittest.main()
