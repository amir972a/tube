import re

class AuthAnalyzer:
    def analyze(self, msg):
        findings = []
        summary = {
            'spf': 'none',
            'dkim': 'none',
            'dmarc': 'none',
            'raw_auth_results': []
        }

        auth_results_headers = msg.get_all('Authentication-Results', [])
        received_spf_headers = msg.get_all('Received-SPF', [])

        if not auth_results_headers and not received_spf_headers:
            findings.append({
                'category': 'Authentication',
                'severity': 'Informational',
                'evidence': "No Authentication-Results or Received-SPF headers found.",
                'explanation': "The receiving server did not record SPF, DKIM, or DMARC authentication results. This means we cannot cryptographically verify the sender's identity from the headers alone.",
                'action': "Rely on other indicators to assess risk."
            })
            return {'summary': summary, 'findings': findings}

        # Combine headers for parsing
        all_auth_text = " ".join(auth_results_headers) + " ".join(received_spf_headers)
        summary['raw_auth_results'] = auth_results_headers + received_spf_headers

        # Simple Regex extraction (Note: standard Authentication-Results parsing can be complex, this is simplified)
        spf_match = re.search(r'spf=(pass|fail|softfail|neutral|none|temperror|permerror)', all_auth_text, re.IGNORECASE)
        dkim_match = re.search(r'dkim=(pass|fail|neutral|none|temperror|permerror)', all_auth_text, re.IGNORECASE)
        dmarc_match = re.search(r'dmarc=(pass|fail|bestguesspass|none|temperror|permerror)', all_auth_text, re.IGNORECASE)

        if spf_match:
            summary['spf'] = spf_match.group(1).lower()
        if dkim_match:
            summary['dkim'] = dkim_match.group(1).lower()
        if dmarc_match:
            summary['dmarc'] = dmarc_match.group(1).lower()

        # Evaluate SPF
        if summary['spf'] in ['fail', 'softfail']:
            findings.append({
                'category': 'Authentication Failure',
                'severity': 'High' if summary['spf'] == 'fail' else 'Medium',
                'evidence': f"SPF Result: {summary['spf']}",
                'explanation': f"The sender's IP address is not authorized to send email on behalf of the domain ({summary['spf']}). This is a strong indicator of spoofing.",
                'action': "Verify the sender. Treat links and attachments as highly suspicious."
            })

        # Evaluate DKIM
        if summary['dkim'] == 'fail':
            findings.append({
                'category': 'Authentication Failure',
                'severity': 'High',
                'evidence': f"DKIM Result: {summary['dkim']}",
                'explanation': "The DKIM cryptographic signature is invalid or has been tampered with in transit. The email content or sender identity may be forged.",
                'action': "Do not trust the sender identity or email contents."
            })

        # Evaluate DMARC
        if summary['dmarc'] == 'fail':
            findings.append({
                'category': 'Authentication Failure',
                'severity': 'High',
                'evidence': f"DMARC Result: {summary['dmarc']}",
                'explanation': "The email failed DMARC alignment, meaning neither SPF nor DKIM passed alignment checks for the 'From' domain. This strongly suggests the 'From' address is spoofed.",
                'action': "Quarantine or reject based on organizational policy."
            })

        return {
            'summary': summary,
            'findings': findings
        }
