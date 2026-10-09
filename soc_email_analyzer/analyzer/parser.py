import email
from email import policy
import logging
from .headers import HeaderAnalyzer
from .auth import AuthAnalyzer
from .urls import URLAnalyzer
from .attachments import AttachmentAnalyzer
from .body import BodyAnalyzer
from .scoring import ScoreEngine
from .spf_investigator import SpfInvestigator

logger = logging.getLogger(__name__)

class EmailParser:
    def __init__(self):
        self.header_analyzer = HeaderAnalyzer()
        self.auth_analyzer = AuthAnalyzer()
        self.url_analyzer = URLAnalyzer()
        self.attachment_analyzer = AttachmentAnalyzer()
        self.body_analyzer = BodyAnalyzer()
        self.score_engine = ScoreEngine()
        self.spf_investigator = SpfInvestigator()

    def parse_file(self, filepath):
        """Parses an .eml file."""
        try:
            with open(filepath, 'rb') as f:
                msg = email.message_from_binary_file(f, policy=policy.default)
            return self._analyze_message(msg)
        except Exception as e:
            logger.error(f"Failed to parse file {filepath}: {e}")
            raise

    def parse_text(self, text):
        """Parses raw email text/headers."""
        try:
            msg = email.message_from_string(text, policy=policy.default)
            return self._analyze_message(msg)
        except Exception as e:
            logger.error(f"Failed to parse text: {e}")
            raise

    def _analyze_message(self, msg):
        """Analyzes a parsed email message object."""
        results = {
            'headers': {},
            'auth': {},
            'urls': [],
            'attachments': [],
            'body': {},
            'findings': [],
            'score': 0,
            'severity': 'Informational',
            'subject': msg.get('Subject', 'No Subject'),
            'sender': msg.get('From', 'Unknown Sender'),
        }

        # 1. Analyze Headers
        header_results = self.header_analyzer.analyze(msg)
        results['headers'] = header_results.get('parsed', {})
        results['findings'].extend(header_results.get('findings', []))

        # 2. Analyze Authentication (SPF/DKIM/DMARC)
        auth_results = self.auth_analyzer.analyze(msg)
        results['auth'] = auth_results.get('summary', {})
        results['findings'].extend(auth_results.get('findings', []))

        # 3. Analyze Body & URLs
        # Extract body parts
        plain_text = ""
        html_text = ""

        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition"))

                # Skip attachments
                if "attachment" in content_disposition:
                    continue

                if content_type == "text/plain":
                    try:
                        plain_text += part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='replace')
                    except:
                        pass
                elif content_type == "text/html":
                    try:
                        html_text += part.get_payload(decode=True).decode(part.get_content_charset() or 'utf-8', errors='replace')
                    except:
                        pass
        else:
            # Not multipart
            content_type = msg.get_content_type()
            try:
                payload = msg.get_payload(decode=True).decode(msg.get_content_charset() or 'utf-8', errors='replace')
                if content_type == "text/html":
                    html_text = payload
                else:
                    plain_text = payload
            except:
                pass

        results['body']['plain'] = plain_text
        results['body']['html'] = html_text

        # Analyze URLs in body
        url_results = self.url_analyzer.analyze(plain_text, html_text)
        results['urls'] = url_results.get('urls', [])
        results['findings'].extend(url_results.get('findings', []))

        # Analyze Body content
        body_results = self.body_analyzer.analyze(plain_text, html_text)
        results['findings'].extend(body_results.get('findings', []))

        # 4. Analyze Attachments
        attachment_results = self.attachment_analyzer.analyze(msg)
        results['attachments'] = attachment_results.get('attachments', [])
        results['findings'].extend(attachment_results.get('findings', []))

        # 5. SPF / DMARC Investigation
        spf_report = self.spf_investigator.investigate(msg, results['headers'], results['auth'])
        results['spf_investigation'] = spf_report

        # 6. Calculate Score
        score, severity, scoring_explanations = self.score_engine.calculate(results['findings'])
        results['score'] = score
        results['severity'] = severity
        results['scoring_explanations'] = scoring_explanations

        return results
