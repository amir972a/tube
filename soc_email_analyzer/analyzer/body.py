import re

class BodyAnalyzer:
    def __init__(self):
        # Keyword dictionaries for different social engineering tactics
        self.urgency_keywords = [
            r'\burgent\b', r'\bimmediate action required\b', r'\bact now\b', r'\baccount suspension\b',
            r'\bwithin 24 hours\b', r'\bfinal warning\b', r'\boverdue\b', r'\bterminate\b'
        ]

        self.credential_keywords = [
            r'\bverify your account\b', r'\bupdate your password\b', r'\blogin to confirm\b',
            r'\bvalidate your credentials\b', r'\bclick here to secure\b', r'\bpassword reset\b'
        ]

        self.financial_keywords = [
            r'\binvoice attached\b', r'\bpayment confirmation\b', r'\bwire transfer\b',
            r'\bpayroll\b', r'\bswift copy\b', r'\bremittance advice\b', r'\boutstanding balance\b'
        ]

    def analyze(self, plain_text, html_text):
        findings = []

        combined_text = (plain_text + " " + html_text).lower()

        if not combined_text.strip():
             return {'findings': findings}

        # 1. Urgency and Threats
        for keyword in self.urgency_keywords:
            if re.search(keyword, combined_text):
                 findings.append({
                    'category': 'Social Engineering',
                    'severity': 'Low',
                    'evidence': f"Keyword matched: '{keyword.replace(r'\\b', '')}'",
                    'explanation': "The email body contains language designed to create a sense of urgency. This is a common tactic to rush users into making mistakes.",
                    'action': "Verify the request through an out-of-band communication channel."
                })
                 break # Only flag once for urgency

        # 2. Credential Harvesting / Account Actions
        for keyword in self.credential_keywords:
            if re.search(keyword, combined_text):
                 findings.append({
                    'category': 'Social Engineering',
                    'severity': 'Medium',
                    'evidence': f"Keyword matched: '{keyword.replace(r'\\b', '')}'",
                    'explanation': "The email body asks the user to verify, update, or log into an account. Phishing emails frequently use this lure to steal credentials.",
                    'action': "Do not click links. Navigate to the service directly via a bookmark."
                })
                 break

        # 3. Financial Lures
        for keyword in self.financial_keywords:
            if re.search(keyword, combined_text):
                 findings.append({
                    'category': 'Social Engineering',
                    'severity': 'Low',
                    'evidence': f"Keyword matched: '{keyword.replace(r'\\b', '')}'",
                    'explanation': "The email references invoices, payments, or wire transfers. This is a common lure for malware distribution or Business Email Compromise (BEC).",
                    'action': "Verify the transaction with the supposed sender or billing department."
                })
                 break

        # 4. HTML Obfuscation / Tricks (Basic checks)
        if html_text:
            # Look for zero-width characters (often used to bypass spam filters)
            if re.search(r'(&#8203;|&#x200B;|&zwnj;|&zwj;)', html_text, re.IGNORECASE):
                findings.append({
                    'category': 'HTML Obfuscation',
                    'severity': 'Medium',
                    'evidence': "Zero-width characters found in HTML",
                    'explanation': "The HTML body contains zero-width or invisible characters. These are often inserted by attackers to break up keywords and evade signature-based spam filters.",
                    'action': "Review the plain text carefully."
                })

            # Look for tracking pixels (1x1 images)
            if re.search(r'<img[^>]+width=[\'"]?1[\'"]?[^>]+height=[\'"]?1[\'"]?', html_text, re.IGNORECASE):
                 findings.append({
                    'category': 'Tracking',
                    'severity': 'Informational',
                    'evidence': "Possible 1x1 tracking pixel detected",
                    'explanation': "The email contains a 1x1 image, likely used as a tracking pixel to notify the sender when the email is opened.",
                    'action': "Ensure external images are blocked by the email client."
                })

            # Suspicious Forms
            if '<form' in html_text.lower():
                action_match = re.search(r'<form[^>]+action=[\'"]?(https?://[^\s>"\']+)[\'"]?', html_text, re.IGNORECASE)
                evidence = "Form found in email."
                if action_match:
                    evidence += f" Posts data to: {action_match.group(1)}"

                findings.append({
                    'category': 'Suspicious Content',
                    'severity': 'High',
                    'evidence': evidence,
                    'explanation': "The email body contains an HTML form. Legitimate organizations rarely put forms directly in emails. This is a technique to collect credentials directly from the inbox.",
                    'action': "Do not enter any information into the form."
                })

        return {'findings': findings}
