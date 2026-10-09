import requests
import json
import os
import logging

logger = logging.getLogger(__name__)

class ThreatIntel:
    """
    Modular threat intelligence integration.
    Designed to be optional, confirmation-gated, and offline-safe.
    """
    def __init__(self):
        # Load config if exists
        self.config_path = "threat_intel_config.json"
        self.api_keys = self._load_config()

    def _load_config(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Failed to load config: {e}")
        return {
            'virustotal': '',
            'urlhaus': ''
        }

    def save_config(self, virustotal_key, urlhaus_key):
        self.api_keys['virustotal'] = virustotal_key
        self.api_keys['urlhaus'] = urlhaus_key
        try:
            with open(self.config_path, 'w') as f:
                json.dump(self.api_keys, f, indent=4)
        except Exception as e:
            logger.error(f"Failed to save config: {e}")

    def lookup_hash_vt(self, sha256_hash):
        """Lookup a hash on VirusTotal."""
        api_key = self.api_keys.get('virustotal')
        if not api_key:
            return {"status": "error", "message": "API key not configured."}

        url = f"https://www.virustotal.com/api/v3/files/{sha256_hash}"
        headers = {
            "accept": "application/json",
            "x-apikey": api_key
        }

        try:
            # We use timeout to avoid hanging the UI
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                total = sum(stats.values())

                return {
                    "status": "success",
                    "source": "VirusTotal",
                    "malicious": malicious,
                    "total": total,
                    "link": f"https://www.virustotal.com/gui/file/{sha256_hash}"
                }
            elif response.status_code == 404:
                return {"status": "success", "source": "VirusTotal", "message": "Hash not found."}
            else:
                return {"status": "error", "message": f"HTTP {response.status_code}"}
        except requests.exceptions.RequestException as e:
            return {"status": "error", "message": f"Connection failed: {str(e)}"}

    def lookup_url_urlhaus(self, url):
        """Lookup a URL on URLhaus."""
        # URLhaus API doesn't strictly require an API key for basic lookups, but we'll mock the integration concept
        api_url = "https://urlhaus-api.abuse.ch/v1/url/"
        data = {'url': url}

        try:
            response = requests.post(api_url, data=data, timeout=10)
            if response.status_code == 200:
                result = response.json()
                if result.get('query_status') == 'ok':
                    return {
                        "status": "success",
                        "source": "URLhaus",
                        "status_tag": result.get('url_status'),
                        "threat": result.get('threat'),
                        "tags": result.get('tags', [])
                    }
                else:
                    return {"status": "success", "source": "URLhaus", "message": "No hit."}
            else:
                return {"status": "error", "message": f"HTTP {response.status_code}"}
        except requests.exceptions.RequestException as e:
            return {"status": "error", "message": f"Connection failed: {str(e)}"}
