import re
import dns.resolver
import ipaddress
import tldextract
import logging
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)

class SpfInvestigator:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5
        self.extract = tldextract.TLDExtract()

    def _extract_ip_from_received(self, received_headers: List[str]) -> Tuple[Optional[str], str]:
        """Extracts the originating client IP from Received headers."""
        if not received_headers:
            return None, "No Received headers available"

        # Simplistic extraction: get the last Received header (the first hop)
        # In a real scenario, this would be more complex and verify internal/external boundaries
        for header in reversed(received_headers):
            # Try to find IPv4
            ip4_match = re.search(r'\[(\d{1,3}(?:\.\d{1,3}){3})\]', header)
            if ip4_match:
                ip = ip4_match.group(1)
                # Exclude private IPs if possible, but for investigation, any IP might be useful
                if not ip.startswith('10.') and not ip.startswith('192.168.') and not re.match(r'172\.(1[6-9]|2[0-9]|3[0-1])\.', ip) and ip != '127.0.0.1':
                    return ip, f"Extracted from Received header: {header[:50]}..."

            # Try IPv6
            ip6_match = re.search(r'\[([0-9a-fA-F:]+)\]', header)
            if ip6_match:
                # Basic validation
                try:
                    ipaddress.IPv6Address(ip6_match.group(1))
                    return ip6_match.group(1), f"Extracted from Received header: {header[:50]}..."
                except ValueError:
                    pass

        # If no public IP found, just return the first IP found in the last header
        header = received_headers[-1] if received_headers else ""
        ip4_match = re.search(r'\[(\d{1,3}(?:\.\d{1,3}){3})\]', header)
        if ip4_match:
            return ip4_match.group(1), "Extracted private/internal IP from Received header"

        return None, "No IP found in Received headers"

    def _get_txt_records(self, domain: str) -> List[str]:
        try:
            answers = self.resolver.resolve(domain, 'TXT')
            records = []
            for rdata in answers:
                txt_string = "".join([s.decode('utf-8') for s in rdata.strings])
                records.append(txt_string)
            return records
        except Exception as e:
            logger.debug(f"DNS TXT lookup failed for {domain}: {e}")
            return []

    def _get_a_records(self, domain: str) -> List[str]:
        try:
            answers = self.resolver.resolve(domain, 'A')
            return [rdata.address for rdata in answers]
        except Exception:
            return []

    def _get_aaaa_records(self, domain: str) -> List[str]:
        try:
            answers = self.resolver.resolve(domain, 'AAAA')
            return [rdata.address for rdata in answers]
        except Exception:
            return []

    def _get_mx_records(self, domain: str) -> List[str]:
        try:
            answers = self.resolver.resolve(domain, 'MX')
            mx_hosts = [rdata.exchange.to_text().rstrip('.') for rdata in answers]
            ips = []
            for mx in mx_hosts:
                ips.extend(self._get_a_records(mx))
                ips.extend(self._get_aaaa_records(mx))
            return ips
        except Exception:
            return []

    def _get_spf_record(self, domain: str) -> Optional[str]:
        records = self._get_txt_records(domain)
        spf_records = [r for r in records if r.startswith('v=spf1')]
        if not spf_records:
            return None
        if len(spf_records) > 1:
            return "permerror: multiple SPF records"
        return spf_records[0]

    def _evaluate_spf(self, domain: str, ip: str, lookup_count: int = 0, trace: List[Dict] = None) -> Tuple[str, str, int, List[Dict]]:
        """
        Evaluates SPF recursively.
        Returns: (result, explanation, lookup_count, trace)
        """
        if trace is None:
            trace = []

        if lookup_count > 10:
            trace.append({'domain': domain, 'mechanism': 'N/A', 'result': 'permerror', 'reason': 'DNS lookup limit exceeded (10)'})
            return 'permerror', "DNS lookup limit exceeded", lookup_count, trace

        spf_record = self._get_spf_record(domain)

        if not spf_record:
            trace.append({'domain': domain, 'mechanism': 'N/A', 'result': 'none', 'reason': 'No SPF record found'})
            return 'none', f"No SPF record found for {domain}", lookup_count, trace

        if spf_record == "permerror: multiple SPF records":
            trace.append({'domain': domain, 'mechanism': 'N/A', 'result': 'permerror', 'reason': 'Multiple SPF records found'})
            return 'permerror', f"Multiple SPF records found for {domain}", lookup_count, trace

        trace.append({'domain': domain, 'mechanism': 'record', 'result': 'info', 'reason': f"Found SPF: {spf_record}"})

        try:
            client_ip_obj = ipaddress.ip_address(ip)
        except ValueError:
             return 'temperror', f"Invalid IP address: {ip}", lookup_count, trace

        mechanisms = spf_record.split()[1:] # Skip v=spf1

        for mech in mechanisms:
            mech_lower = mech.lower()
            qualifier = '+'
            if mech.startswith(('-', '~', '?', '+')):
                qualifier = mech[0]
                mech = mech[1:]
                mech_lower = mech_lower[1:]

            result_map = {'+': 'pass', '-': 'fail', '~': 'softfail', '?': 'neutral'}
            matched_result = result_map.get(qualifier, 'pass')

            if mech_lower == 'all':
                trace.append({'domain': domain, 'mechanism': f"{qualifier}all", 'result': matched_result, 'reason': "Matched 'all' mechanism"})
                return matched_result, f"Matched {qualifier}all", lookup_count, trace

            elif mech_lower.startswith('ip4:') or mech_lower.startswith('ip6:'):
                prefix = mech[4:]
                try:
                    network = ipaddress.ip_network(prefix, strict=False)
                    if client_ip_obj in network:
                         trace.append({'domain': domain, 'mechanism': mech, 'result': matched_result, 'reason': f"IP {ip} is in network {prefix}"})
                         return matched_result, f"Matched IP network {prefix}", lookup_count, trace
                except ValueError:
                    pass

            elif mech_lower.startswith('a'):
                lookup_count += 1
                if lookup_count > 10: return 'permerror', "DNS lookup limit exceeded", lookup_count, trace

                target_domain = domain
                if ':' in mech:
                    target_domain = mech.split(':', 1)[1]

                # Handle CIDR
                cidr = None
                if '/' in target_domain:
                    parts = target_domain.split('/')
                    target_domain = parts[0]
                    cidr = parts[1]

                ips = self._get_a_records(target_domain) + self._get_aaaa_records(target_domain)

                for a_ip in ips:
                    if cidr:
                        try:
                            network = ipaddress.ip_network(f"{a_ip}/{cidr}", strict=False)
                            if client_ip_obj in network:
                                trace.append({'domain': domain, 'mechanism': mech, 'result': matched_result, 'reason': f"IP {ip} matched A record {a_ip} with CIDR /{cidr}"})
                                return matched_result, f"Matched A mechanism for {target_domain}", lookup_count, trace
                        except ValueError:
                            pass
                    else:
                        if ip == a_ip:
                            trace.append({'domain': domain, 'mechanism': mech, 'result': matched_result, 'reason': f"IP {ip} matched A record {a_ip}"})
                            return matched_result, f"Matched A mechanism for {target_domain}", lookup_count, trace

            elif mech_lower.startswith('mx'):
                lookup_count += 1
                if lookup_count > 10: return 'permerror', "DNS lookup limit exceeded", lookup_count, trace

                target_domain = domain
                if ':' in mech:
                    target_domain = mech.split(':', 1)[1]

                cidr = None
                if '/' in target_domain:
                    parts = target_domain.split('/')
                    target_domain = parts[0]
                    cidr = parts[1]

                ips = self._get_mx_records(target_domain)

                for mx_ip in ips:
                    if cidr:
                        try:
                            network = ipaddress.ip_network(f"{mx_ip}/{cidr}", strict=False)
                            if client_ip_obj in network:
                                trace.append({'domain': domain, 'mechanism': mech, 'result': matched_result, 'reason': f"IP {ip} matched MX record {mx_ip} with CIDR /{cidr}"})
                                return matched_result, f"Matched MX mechanism for {target_domain}", lookup_count, trace
                        except ValueError:
                            pass
                    else:
                        if ip == mx_ip:
                            trace.append({'domain': domain, 'mechanism': mech, 'result': matched_result, 'reason': f"IP {ip} matched MX record {mx_ip}"})
                            return matched_result, f"Matched MX mechanism for {target_domain}", lookup_count, trace

            elif mech_lower.startswith('include:'):
                lookup_count += 1
                if lookup_count > 10: return 'permerror', "DNS lookup limit exceeded", lookup_count, trace

                target_domain = mech.split(':', 1)[1]
                trace.append({'domain': domain, 'mechanism': mech, 'result': 'info', 'reason': f"Evaluating include: {target_domain}"})

                inc_res, inc_exp, lookup_count, trace = self._evaluate_spf(target_domain, ip, lookup_count, trace)

                if inc_res == 'pass':
                    trace.append({'domain': domain, 'mechanism': mech, 'result': matched_result, 'reason': f"Include {target_domain} resulted in pass"})
                    return matched_result, f"Matched include {target_domain}", lookup_count, trace
                elif inc_res in ['permerror', 'temperror']:
                    return inc_res, inc_exp, lookup_count, trace
                # If include does not return pass/permerror/temperror, SPF evaluation continues.

        # Check for redirect modifier
        redirect_modifier = next((m for m in mechanisms if m.lower().startswith('redirect=')), None)
        if redirect_modifier:
            lookup_count += 1
            if lookup_count > 10: return 'permerror', "DNS lookup limit exceeded", lookup_count, trace
            target_domain = redirect_modifier.split('=', 1)[1]
            trace.append({'domain': domain, 'mechanism': redirect_modifier, 'result': 'info', 'reason': f"Following redirect to: {target_domain}"})
            return self._evaluate_spf(target_domain, ip, lookup_count, trace)

        trace.append({'domain': domain, 'mechanism': 'N/A', 'result': 'neutral', 'reason': 'No matching mechanism found (default neutral)'})
        return 'neutral', "No matching mechanism found", lookup_count, trace

    def _get_org_domain(self, domain: str) -> str:
        extracted = self.extract(domain)
        return f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else domain

    def _check_alignment(self, domain1: str, domain2: str, strict: bool = False) -> bool:
        if not domain1 or not domain2:
            return False
        domain1 = domain1.lower()
        domain2 = domain2.lower()

        if strict:
            return domain1 == domain2
        else:
            return self._get_org_domain(domain1) == self._get_org_domain(domain2)

    def _get_dmarc_record(self, domain: str) -> Optional[Dict[str, str]]:
        org_domain = self._get_org_domain(domain)

        # Try exact domain first
        dmarc_domain = f"_dmarc.{domain}"
        records = self._get_txt_records(dmarc_domain)
        dmarc_records = [r for r in records if r.startswith('v=DMARC1')]

        # Fallback to org domain if different
        if not dmarc_records and domain != org_domain:
             dmarc_domain = f"_dmarc.{org_domain}"
             records = self._get_txt_records(dmarc_domain)
             dmarc_records = [r for r in records if r.startswith('v=DMARC1')]

        if not dmarc_records:
            return None

        record = dmarc_records[0]
        parsed = {'raw': record}

        parts = record.split(';')
        for part in parts:
            part = part.strip()
            if '=' in part:
                k, v = part.split('=', 1)
                parsed[k.strip()] = v.strip()

        return parsed

    def investigate(self, msg, parsed_headers: Dict[str, Any], auth_summary: Dict[str, str]) -> Dict[str, Any]:
        """Performs the full SPF/DMARC investigation."""
        report = {
            'visible_from_domain': None,
            'envelope_sender_domain': None,
            'client_ip': None,
            'client_ip_source': None,
            'original_spf_result': auth_summary.get('spf', 'none'),
            'dmarc': {
                'record': None,
                'policy': 'none',
                'spf_alignment': 'NOT ALIGNED',
                'dkim_alignment': 'NOT ALIGNED',
                'overall_result': 'NOT VERIFIED'
            },
            'investigations': {
                'original_auth': {
                    'evaluated_domain': None,
                    'result': 'NOT VERIFIED',
                    'explanation': '',
                    'trace': []
                },
                'visible_from_auth': {
                    'evaluated_domain': None,
                    'result': 'NOT VERIFIED',
                    'explanation': '',
                    'trace': []
                }
            }
        }

        # 1. Identify Identities
        from_header = parsed_headers.get('From', '')
        from_match = re.search(r'<[^>]*@([^>]+)>', from_header) or re.search(r'@([^\s>]+)', from_header)
        if from_match:
            report['visible_from_domain'] = from_match.group(1).lower()

        return_path = parsed_headers.get('Return-Path', '')
        rp_match = re.search(r'<[^>]*@([^>]+)>', return_path) or re.search(r'@([^\s>]+)', return_path)
        if rp_match:
            report['envelope_sender_domain'] = rp_match.group(1).lower()

        if not report['envelope_sender_domain']:
            # Fallback to Authentication-Results if available
            auth_results = "\n".join(msg.get_all('Authentication-Results', []))
            spf_match = re.search(r'spf=\w+ \([^)]*smtp\.mailfrom=([^)\s]+)', auth_results, re.IGNORECASE)
            if spf_match:
                 report['envelope_sender_domain'] = spf_match.group(1).lower()

        if not report['envelope_sender_domain']:
             report['envelope_sender_domain'] = report['visible_from_domain'] # Last resort fallback

        # Extract IP
        received_headers = msg.get_all('Received', [])
        ip, source = self._extract_ip_from_received(received_headers)
        report['client_ip'] = ip
        report['client_ip_source'] = source

        # 2. SPF Investigations
        if ip:
            # A. Original Authentication (Envelope Sender)
            if report['envelope_sender_domain']:
                res, exp, _, trace = self._evaluate_spf(report['envelope_sender_domain'], ip)
                report['investigations']['original_auth'] = {
                    'evaluated_domain': report['envelope_sender_domain'],
                    'result': res.upper(),
                    'explanation': exp,
                    'trace': trace
                }

            # B. Visible From Domain Authorization
            if report['visible_from_domain'] and report['visible_from_domain'] != report['envelope_sender_domain']:
                 res, exp, _, trace = self._evaluate_spf(report['visible_from_domain'], ip)
                 report['investigations']['visible_from_auth'] = {
                    'evaluated_domain': report['visible_from_domain'],
                    'result': res.upper(),
                    'explanation': exp,
                    'trace': trace
                }
            elif report['visible_from_domain'] == report['envelope_sender_domain']:
                 # If they are the same, copy the result to avoid redundant lookup
                 report['investigations']['visible_from_auth'] = report['investigations']['original_auth']

        else:
            report['investigations']['original_auth']['explanation'] = "Cannot evaluate: No Client IP found."
            report['investigations']['visible_from_auth']['explanation'] = "Cannot evaluate: No Client IP found."

        # 3. DMARC and Alignment
        if report['visible_from_domain']:
            dmarc_record = self._get_dmarc_record(report['visible_from_domain'])
            if dmarc_record:
                report['dmarc']['record'] = dmarc_record.get('raw')
                report['dmarc']['policy'] = dmarc_record.get('p', 'none')

                # SPF Alignment
                spf_mode = dmarc_record.get('aspf', 'r') # default relaxed
                is_strict = spf_mode == 's'

                # Use the actual evaluated SPF result if we have it, otherwise fallback to the header-reported one
                eval_spf_result = report['investigations']['original_auth']['result'].lower()
                spf_pass = eval_spf_result == 'pass' or auth_summary.get('spf') == 'pass'

                if spf_pass and report['envelope_sender_domain']:
                    aligned = self._check_alignment(report['visible_from_domain'], report['envelope_sender_domain'], strict=is_strict)
                    report['dmarc']['spf_alignment'] = 'ALIGNED' if aligned else 'NOT ALIGNED'
                else:
                    report['dmarc']['spf_alignment'] = 'NOT ALIGNED (SPF FAIL)'

                # DKIM Alignment (Simplified based on headers, as we don't perform crypto validation here)
                dkim_pass = auth_summary.get('dkim') == 'pass'
                dkim_aligned = False

                # Try to find the dkim domain from auth results
                auth_results = "\n".join(msg.get_all('Authentication-Results', []))
                dkim_matches = re.finditer(r'dkim=pass [^;]*header\.d=([^;\s]+)', auth_results, re.IGNORECASE)

                for match in dkim_matches:
                    dkim_domain = match.group(1).lower()
                    adkim = dmarc_record.get('adkim', 'r')
                    if self._check_alignment(report['visible_from_domain'], dkim_domain, strict=(adkim=='s')):
                        dkim_aligned = True
                        break

                if dkim_pass:
                    report['dmarc']['dkim_alignment'] = 'ALIGNED' if dkim_aligned else 'NOT ALIGNED'
                else:
                    report['dmarc']['dkim_alignment'] = 'NOT ALIGNED (DKIM FAIL)'

                # Overall DMARC Result
                if report['dmarc']['spf_alignment'] == 'ALIGNED' or report['dmarc']['dkim_alignment'] == 'ALIGNED':
                     report['dmarc']['overall_result'] = 'PASS'
                else:
                     report['dmarc']['overall_result'] = 'FAIL'

        return report
