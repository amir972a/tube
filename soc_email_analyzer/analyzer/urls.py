import re
from urllib.parse import urlparse, unquote

class URLAnalyzer:
    def __init__(self):
        # Common URL shorteners
        self.shorteners = [
            'bit.ly', 't.co', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd',
            'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee', 'su.pr'
        ]

    def defang_url(self, url):
        """Safely defangs a URL for display."""
        defanged = url.replace('http://', 'hxxp://').replace('https://', 'hxxps://')
        defanged = defanged.replace('.', '[.]')
        return defanged

    def analyze(self, plain_text, html_text):
        findings = []
        urls = set()

        # 1. Extract URLs from plain text and HTML
        # Simple extraction regex
        url_pattern = re.compile(r'(https?://[^\s<>"\'{}|\\^~\[\]`]+)')

        if plain_text:
            urls.update(url_pattern.findall(plain_text))

        if html_text:
            # Extract from href attributes specifically to find mismatches later
            href_pattern = re.compile(r'href=[\'"]?(https?://[^\s>\'"]+)[\'"]?', re.IGNORECASE)
            urls.update(href_pattern.findall(html_text))

            # Also get raw urls in text
            urls.update(url_pattern.findall(html_text))

            # Check for Link Text vs Href Mismatch
            link_tags = re.findall(r'<a\s+[^>]*href=[\'"]?([^\'" >]+)[\'"]?[^>]*>(.*?)</a>', html_text, re.IGNORECASE | re.DOTALL)
            for href, link_text in link_tags:
                # Clean up html tags inside link text
                clean_text = re.sub(r'<[^>]+>', '', link_text).strip()
                # If the visible text looks like a URL, compare domains
                if re.match(r'^https?://', clean_text) or re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', clean_text):
                    try:
                        href_domain = urlparse(href if href.startswith('http') else f"http://{href}").netloc
                        text_domain = urlparse(clean_text if clean_text.startswith('http') else f"http://{clean_text}").netloc

                        # Remove www. for comparison
                        href_domain = href_domain.replace('www.', '')
                        text_domain = text_domain.replace('www.', '')

                        if text_domain and href_domain and text_domain != href_domain:
                            findings.append({
                                'category': 'URL Anomaly',
                                'severity': 'High',
                                'evidence': f"Visible: {clean_text}, Actual Destination: {self.defang_url(href)}",
                                'explanation': "The visible link text shows a different domain than the actual destination. This is a classic phishing technique to deceive the user.",
                                'action': "Do not click the link. Treat as malicious."
                            })
                    except:
                        pass

        analyzed_urls = []
        for url in urls:
            try:
                parsed = urlparse(url)
                domain = parsed.netloc.lower()

                url_data = {
                    'raw': url,
                    'defanged': self.defang_url(url),
                    'domain': domain,
                    'scheme': parsed.scheme
                }

                # Check for IP address in URL
                if re.match(r'^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}(:\d+)?$', domain):
                     findings.append({
                        'category': 'Suspicious URL',
                        'severity': 'Medium',
                        'evidence': f"URL: {self.defang_url(url)}",
                        'explanation': "The URL uses an IP address instead of a domain name. Legitimate services rarely use bare IP addresses in emails.",
                        'action': "Investigate the IP address reputation."
                    })

                # Check for URL shorteners
                if domain in self.shorteners or domain.startswith('www.') and domain[4:] in self.shorteners:
                    findings.append({
                        'category': 'Suspicious URL',
                        'severity': 'Low',
                        'evidence': f"URL: {self.defang_url(url)}",
                        'explanation': "A URL shortener service is used. While often legitimate, attackers use them to hide the true destination of a malicious link.",
                        'action': "Expand the URL safely using a tool before visiting."
                    })

                # Check for unusual ports
                if ':' in domain:
                    port = domain.split(':')[1]
                    if port not in ['80', '443']:
                        findings.append({
                            'category': 'Suspicious URL',
                            'severity': 'Low',
                            'evidence': f"URL: {self.defang_url(url)}, Port: {port}",
                            'explanation': f"The URL connects to an unusual port ({port}). Most legitimate web traffic uses port 80 or 443.",
                            'action': "Verify if this service is expected to operate on a non-standard port."
                        })

                # Check for User Info (e.g., http://google.com-login@attacker.com)
                if '@' in parsed.netloc:
                     findings.append({
                        'category': 'Suspicious URL',
                        'severity': 'High',
                        'evidence': f"URL: {self.defang_url(url)}",
                        'explanation': "The URL contains embedded credentials (user@domain). Attackers use this to make the visible part of the URL look like a trusted site, while redirecting to their server.",
                        'action': "Treat as highly suspicious."
                    })

                analyzed_urls.append(url_data)
            except Exception as e:
                # Parsing failed, skip analysis for this url
                continue

        return {
            'urls': analyzed_urls,
            'findings': findings
        }
