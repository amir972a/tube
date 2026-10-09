import re
from email.utils import parseaddr, getaddresses

class HeaderAnalyzer:
    def analyze(self, msg):
        findings = []
        parsed_headers = {}

        # Extract common headers
        headers_to_extract = [
            'From', 'Reply-To', 'Return-Path', 'To', 'Subject',
            'Date', 'Message-ID', 'Received', 'Authentication-Results',
            'Received-SPF', 'DKIM-Signature', 'MIME-Version', 'Content-Type'
        ]

        for header in headers_to_extract:
            values = msg.get_all(header)
            if values:
                if len(values) == 1:
                    parsed_headers[header] = values[0]
                else:
                    parsed_headers[header] = values

        # 1. Analyze Mismatches (From vs Reply-To vs Return-Path)
        from_header = msg.get('From', '')
        reply_to_header = msg.get('Reply-To', '')
        return_path_header = msg.get('Return-Path', '')

        _, from_email = parseaddr(from_header)
        _, reply_to_email = parseaddr(reply_to_header)
        _, return_path_email = parseaddr(return_path_header)

        from_domain = from_email.split('@')[1].lower() if '@' in from_email else ''
        reply_to_domain = reply_to_email.split('@')[1].lower() if '@' in reply_to_email else ''
        return_path_domain = return_path_email.split('@')[1].lower() if '@' in return_path_email else ''

        if reply_to_email and from_email and reply_to_email.lower() != from_email.lower():
            if reply_to_domain != from_domain:
                findings.append({
                    'category': 'Header Anomaly',
                    'severity': 'High',
                    'evidence': f"From: {from_email}, Reply-To: {reply_to_email}",
                    'explanation': "The Reply-To domain differs from the From domain. This is a common technique to route replies to an attacker's address while appearing to come from a legitimate source.",
                    'action': "Verify if the Reply-To address is expected or authorized."
                })
            else:
                findings.append({
                    'category': 'Header Anomaly',
                    'severity': 'Low',
                    'evidence': f"From: {from_email}, Reply-To: {reply_to_email}",
                    'explanation': "The Reply-To address differs from the From address, but shares the same domain.",
                    'action': "Investigate if this is a standard configuration for this sender."
                })

        if return_path_email and from_email and return_path_domain != from_domain:
             findings.append({
                'category': 'Header Anomaly',
                'severity': 'Medium',
                'evidence': f"From: {from_domain}, Return-Path: {return_path_domain}",
                'explanation': "The Return-Path (envelope sender) domain differs from the From (header sender) domain. This often indicates the use of an email service provider, but can also be used in spoofing.",
                'action': "Check authentication results (SPF/DKIM) to ensure the Return-Path is authorized to send on behalf of the From domain."
             })

        # 2. Display Name Spoofing
        from_name, _ = parseaddr(from_header)
        if from_name:
            # Check if the display name contains an email address that differs from the actual email
            emails_in_name = re.findall(r'[\w\.-]+@[\w\.-]+', from_name)
            for email_in_name in emails_in_name:
                if email_in_name.lower() != from_email.lower():
                     findings.append({
                        'category': 'Display Name Spoofing',
                        'severity': 'Critical',
                        'evidence': f"Display Name: '{from_name}', Actual Email: {from_email}",
                        'explanation': "The display name contains an email address different from the actual sender address. This is a strong indicator of an attempt to deceive the recipient.",
                        'action': "Treat the email as highly suspicious. Warn the user."
                     })
                     break

        # 3. Missing Message-ID
        message_id = msg.get('Message-ID')
        if not message_id:
            findings.append({
                'category': 'Header Anomaly',
                'severity': 'Low',
                'evidence': "Missing Message-ID header",
                'explanation': "The Message-ID header is missing. While not definitively malicious, legitimate mail servers almost always generate a Message-ID. Its absence might indicate a poorly configured custom script or spam tool.",
                'action': "Look for other anomalies."
            })

        # 4. Analyze Received Headers (Basic)
        received_headers = msg.get_all('Received', [])
        if not received_headers:
            findings.append({
                'category': 'Header Anomaly',
                'severity': 'Medium',
                'evidence': "No Received headers found",
                'explanation': "No 'Received' headers are present. This means the email was not processed by standard mail transport agents, which is highly unusual for internet-routed mail.",
                'action': "Treat with suspicion unless the email is internally generated."
            })

        return {
            'parsed': parsed_headers,
            'findings': findings
        }
