import json
import os
from datetime import datetime
import html

class ReportExporter:
    def export_json(self, analysis_results, filepath):
        """Exports analysis results to a JSON file."""
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(analysis_results, f, indent=4, ensure_ascii=False)

    def export_txt(self, analysis_results, filepath):
        """Exports analysis results to a professional TXT report."""
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

        lines = []
        lines.append("="*60)
        lines.append(" SOC EMAIL THREAT ANALYSIS REPORT ".center(60, "="))
        lines.append("="*60)
        lines.append(f"Analysis Time : {timestamp}")
        lines.append(f"Subject       : {analysis_results.get('subject', 'N/A')}")
        lines.append(f"Sender        : {analysis_results.get('sender', 'N/A')}")
        lines.append(f"Risk Score    : {analysis_results.get('score', 0)}/100")
        lines.append(f"Severity      : {analysis_results.get('severity', 'Unknown')}")
        lines.append("="*60)

        lines.append("\n[ SCORING EXPLANATION ]")
        for exp in analysis_results.get('scoring_explanations', []):
            lines.append(f"  * {exp}")

        lines.append("\n[ AUTHENTICATION SUMMARY ]")
        auth = analysis_results.get('auth', {})
        lines.append(f"  SPF   : {auth.get('spf', 'N/A')}")
        lines.append(f"  DKIM  : {auth.get('dkim', 'N/A')}")
        lines.append(f"  DMARC : {auth.get('dmarc', 'N/A')}")

        lines.append("\n[ KEY FINDINGS ]")
        findings = analysis_results.get('findings', [])
        if findings:
            for i, f in enumerate(findings, 1):
                lines.append(f"\n  Finding {i}: {f.get('category')} ({f.get('severity')})")
                lines.append(f"    Evidence    : {f.get('evidence')}")
                lines.append(f"    Explanation : {f.get('explanation')}")
                lines.append(f"    Action      : {f.get('action')}")
        else:
            lines.append("  No suspicious indicators found.")

        lines.append("\n[ EXTRACTED URLs (Defanged) ]")
        urls = analysis_results.get('urls', [])
        if urls:
            for u in urls:
                lines.append(f"  - {u.get('defanged')}")
        else:
            lines.append("  None found.")

        lines.append("\n[ ATTACHMENTS ]")
        attachments = analysis_results.get('attachments', [])
        if attachments:
            for a in attachments:
                lines.append(f"\n  Filename : {a.get('filename')}")
                lines.append(f"  Type     : {a.get('content_type')}")
                lines.append(f"  Size     : {a.get('size')} bytes")
                lines.append(f"  SHA-256  : {a.get('sha256')}")
        else:
            lines.append("  None found.")

        lines.append("\n" + "="*60)
        lines.append(" END OF REPORT ".center(60, "="))
        lines.append("="*60)

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write("\n".join(lines))

    def export_html(self, analysis_results, filepath):
        """Exports analysis results to an HTML report."""
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')

        # Determine color for severity
        sev = analysis_results.get('severity', 'Informational')
        colors = {
            'Critical': '#dc3545',
            'High': '#fd7e14',
            'Medium': '#ffc107',
            'Low': '#17a2b8',
            'Informational': '#6c757d'
        }
        color = colors.get(sev, '#6c757d')

        html_content = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>SOC Email Threat Report</title>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1000px; margin: 0 auto; padding: 20px; }}
                h1, h2, h3 {{ color: #2c3e50; border-bottom: 2px solid #eee; padding-bottom: 5px; }}
                .summary {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; border-left: 5px solid {color}; }}
                .finding {{ background: #fff; border: 1px solid #ddd; padding: 15px; margin-bottom: 15px; border-radius: 4px; box-shadow: 0 2px 4px rgba(0,0,0,0.05); }}
                .finding-title {{ font-weight: bold; font-size: 1.1em; margin-bottom: 10px; }}
                .badge {{ display: inline-block; padding: 3px 8px; font-size: 0.85em; font-weight: bold; border-radius: 3px; color: #fff; }}
                .badge-Critical {{ background-color: #dc3545; }}
                .badge-High {{ background-color: #fd7e14; }}
                .badge-Medium {{ background-color: #ffc107; color: #212529; }}
                .badge-Low {{ background-color: #17a2b8; }}
                .badge-Informational {{ background-color: #6c757d; }}
                table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .url-list {{ word-break: break-all; font-family: monospace; }}
            </style>
        </head>
        <body>
            <h1>SOC Email Threat Analysis Report</h1>

            <div class="summary">
                <p><strong>Analysis Time:</strong> {timestamp}</p>
                <p><strong>Subject:</strong> {html.escape(str(analysis_results.get('subject', 'N/A')))}</p>
                <p><strong>Sender:</strong> {html.escape(str(analysis_results.get('sender', 'N/A')))}</p>
                <p><strong>Risk Score:</strong> <span style="font-size: 1.2em; font-weight: bold; color: {color};">{analysis_results.get('score', 0)}/100</span></p>
                <p><strong>Severity:</strong> <span class="badge badge-{sev}">{sev}</span></p>
            </div>

            <h2>Authentication Summary</h2>
            <table>
                <tr><th>Protocol</th><th>Result</th></tr>
                <tr><td>SPF</td><td>{html.escape(analysis_results.get('auth', {}).get('spf', 'N/A'))}</td></tr>
                <tr><td>DKIM</td><td>{html.escape(analysis_results.get('auth', {}).get('dkim', 'N/A'))}</td></tr>
                <tr><td>DMARC</td><td>{html.escape(analysis_results.get('auth', {}).get('dmarc', 'N/A'))}</td></tr>
            </table>

            <h2>Key Findings</h2>
        """

        findings = analysis_results.get('findings', [])
        if findings:
            for f in findings:
                f_sev = f.get('severity', 'Informational')
                html_content += f"""
                <div class="finding">
                    <div class="finding-title">
                        {html.escape(f.get('category', 'Unknown'))}
                        <span class="badge badge-{f_sev}">{f_sev}</span>
                    </div>
                    <p><strong>Evidence:</strong> {html.escape(str(f.get('evidence', '')))}</p>
                    <p><strong>Explanation:</strong> {html.escape(str(f.get('explanation', '')))}</p>
                    <p><strong>Action:</strong> {html.escape(str(f.get('action', '')))}</p>
                </div>
                """
        else:
            html_content += "<p>No suspicious indicators found.</p>"

        html_content += "<h2>Extracted URLs (Defanged)</h2>"
        urls = analysis_results.get('urls', [])
        if urls:
            html_content += "<ul>"
            for u in urls:
                html_content += f"<li class='url-list'>{html.escape(u.get('defanged', ''))}</li>"
            html_content += "</ul>"
        else:
            html_content += "<p>None found.</p>"

        html_content += "<h2>Attachments</h2>"
        attachments = analysis_results.get('attachments', [])
        if attachments:
            html_content += "<table><tr><th>Filename</th><th>Type</th><th>Size</th><th>SHA-256</th></tr>"
            for a in attachments:
                html_content += f"""
                <tr>
                    <td>{html.escape(a.get('filename', ''))}</td>
                    <td>{html.escape(a.get('content_type', ''))}</td>
                    <td>{a.get('size', 0)} bytes</td>
                    <td class="url-list">{html.escape(a.get('sha256', ''))}</td>
                </tr>
                """
            html_content += "</table>"
        else:
            html_content += "<p>None found.</p>"

        html_content += """
            <hr>
            <p style="text-align: center; font-size: 0.9em; color: #777;">
                Generated by SOC Email Analyzer.
                <br><em>Disclaimer: Automated analysis should be reviewed by a human analyst.</em>
            </p>
        </body>
        </html>
        """

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
