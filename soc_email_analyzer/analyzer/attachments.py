import hashlib
import os

class AttachmentAnalyzer:
    def __init__(self):
        # List of potentially dangerous extensions
        self.dangerous_extensions = [
            '.exe', '.bat', '.cmd', '.com', '.vbs', '.vbe', '.js', '.jse', '.wsf', '.wsh',
            '.ps1', '.ps1xml', '.ps2', '.ps2xml', '.psc1', '.psc2', '.msh', '.msh1', '.msh2', '.mshxml', '.msh1xml', '.msh2xml',
            '.scf', '.scr', '.sys', '.dll', '.msi', '.msp', '.jar', '.py', '.rb', '.pl', '.sh',
            '.docm', '.xlsm', '.pptm', '.xlam', '.xla', '.xlsb', # Macro-enabled Office
            '.iso', '.img', '.cab', '.zip', '.rar', '.7z', '.tar', '.gz' # Archives (often contain malware)
        ]

    def analyze(self, msg):
        findings = []
        attachments = []

        if not msg.is_multipart():
            return {'attachments': attachments, 'findings': findings}

        for part in msg.walk():
            # Skip multipart containers
            if part.get_content_maintype() == 'multipart':
                continue

            filename = part.get_filename()
            if not filename:
                # Could be inline content, we only care about named attachments here
                continue

            content_type = part.get_content_type()
            payload = part.get_payload(decode=True)

            if payload is None:
                continue

            size = len(payload)
            sha256_hash = hashlib.sha256(payload).hexdigest()

            # Extension analysis
            _, ext = os.path.splitext(filename)
            ext = ext.lower()

            attachment_info = {
                'filename': filename,
                'content_type': content_type,
                'extension': ext,
                'size': size,
                'sha256': sha256_hash,
                'payload': payload
            }
            attachments.append(attachment_info)

            # 1. Dangerous Extensions
            if ext in self.dangerous_extensions:
                 findings.append({
                    'category': 'Suspicious Attachment',
                    'severity': 'High',
                    'evidence': f"Filename: {filename}",
                    'explanation': f"The attachment has a potentially dangerous extension ({ext}). This file type can execute code or scripts on the user's machine.",
                    'action': "Do not open. Submit hash to threat intelligence or analyze in a sandbox."
                })

            # 2. Double Extensions (e.g., invoice.pdf.exe)
            # Naive check: split by '.' and see if there are more than 2 parts and the last is dangerous
            parts = filename.split('.')
            if len(parts) > 2:
                last_ext = "." + parts[-1].lower()
                prev_ext = "." + parts[-2].lower()

                # Check if it's trying to hide an executable as a document
                document_exts = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.txt']
                if prev_ext in document_exts and last_ext in self.dangerous_extensions:
                    findings.append({
                        'category': 'Suspicious Attachment',
                        'severity': 'Critical',
                        'evidence': f"Filename: {filename}",
                        'explanation': "The attachment uses a double extension to trick the user into thinking it's a safe document (e.g., .pdf) while actually being executable.",
                        'action': "Do not open. Highly indicative of malware."
                    })

            # 3. Mismatch between Content-Type and Extension
            # (Basic check, can be expanded)
            if ext == '.exe' and 'application/x-msdownload' not in content_type and 'application/octet-stream' not in content_type:
                 findings.append({
                    'category': 'Attachment Anomaly',
                    'severity': 'Medium',
                    'evidence': f"Filename: {filename}, Content-Type: {content_type}",
                    'explanation': "The declared MIME type does not match the file extension. Attackers sometimes do this to bypass basic filters.",
                    'action': "Inspect the file contents cautiously."
                })

        return {
            'attachments': attachments,
            'findings': findings
        }
