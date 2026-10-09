import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import os
import json
from ..analyzer.parser import EmailParser
from ..db.database import Database
from ..report.exporter import ReportExporter
from ..threat_intel.integrations import ThreatIntel

class ModernTheme:
    """Dark theme colors for the GUI."""
    BG = "#1e1e2e"
    FG = "#cdd6f4"
    ACCENT = "#89b4fa"
    WARN = "#f9e2af"
    ERROR = "#f38ba8"
    PANEL_BG = "#313244"
    TEXT_BG = "#181825"

class EmailAnalyzerGUI(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("SOC Email Threat Analyzer / تحلیل‌گر تهدیدات ایمیل SOC")
        self.geometry("1200x800")
        self.configure(bg=ModernTheme.BG)

        # Modules
        self.parser = EmailParser()
        self.db = Database()
        self.exporter = ReportExporter()
        self.ti = ThreatIntel()

        self.current_analysis = None

        self._setup_styles()
        self._build_ui()

    def _setup_styles(self):
        style = ttk.Style(self)
        style.theme_use('clam')

        style.configure(".", background=ModernTheme.BG, foreground=ModernTheme.FG, font=('Segoe UI', 10))
        style.configure("TNotebook", background=ModernTheme.BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=ModernTheme.PANEL_BG, foreground=ModernTheme.FG, padding=[15, 5])
        style.map("TNotebook.Tab", background=[("selected", ModernTheme.ACCENT)], foreground=[("selected", ModernTheme.BG)])

        style.configure("TFrame", background=ModernTheme.BG)
        style.configure("Panel.TFrame", background=ModernTheme.PANEL_BG)

        style.configure("TButton", background=ModernTheme.PANEL_BG, foreground=ModernTheme.FG, borderwidth=1, padding=5)
        style.map("TButton", background=[("active", ModernTheme.ACCENT)], foreground=[("active", ModernTheme.BG)])

        style.configure("TLabel", background=ModernTheme.BG, foreground=ModernTheme.FG)
        style.configure("Header.TLabel", font=('Segoe UI', 12, 'bold'))

        style.configure("Treeview", background=ModernTheme.TEXT_BG, foreground=ModernTheme.FG, fieldbackground=ModernTheme.TEXT_BG)
        style.configure("Treeview.Heading", background=ModernTheme.PANEL_BG, foreground=ModernTheme.FG, font=('Segoe UI', 10, 'bold'))

    def _build_ui(self):
        # Top Bar
        top_frame = ttk.Frame(self, style="Panel.TFrame")
        top_frame.pack(fill=tk.X, padx=10, pady=10)

        ttk.Button(top_frame, text="Open .eml File (باز کردن فایل)", command=self._open_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(top_frame, text="Clear (پاک کردن)", command=self._clear_all).pack(side=tk.LEFT, padx=5)

        # Threat Intel Button
        ttk.Button(top_frame, text="Threat Intel Settings", command=self._open_ti_settings).pack(side=tk.RIGHT, padx=5)

        # Progress
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(top_frame, variable=self.progress_var, maximum=100)
        self.progress_bar.pack(side=tk.RIGHT, fill=tk.X, expand=True, padx=20)

        self.status_label = ttk.Label(top_frame, text="Ready / آماده", style="Header.TLabel", background=ModernTheme.PANEL_BG)
        self.status_label.pack(side=tk.RIGHT, padx=10)

        # Main Layout
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        # Tabs
        self._build_overview_tab()
        self._build_headers_tab()
        self._build_spf_tab()
        self._build_findings_tab()
        self._build_urls_tab()
        self._build_attachments_tab()
        self._build_history_tab()

    def _build_overview_tab(self):
        self.tab_overview = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_overview, text="Overview / خلاصه")

        # Risk Score Panel
        score_frame = ttk.Frame(self.tab_overview, style="Panel.TFrame")
        score_frame.pack(fill=tk.X, padx=10, pady=10)

        self.lbl_score = ttk.Label(score_frame, text="Risk Score: N/A", font=('Segoe UI', 18, 'bold'), background=ModernTheme.PANEL_BG)
        self.lbl_score.pack(pady=10)

        self.lbl_severity = ttk.Label(score_frame, text="Severity: N/A", font=('Segoe UI', 14), background=ModernTheme.PANEL_BG)
        self.lbl_severity.pack(pady=5)

        # Meta Info
        info_frame = ttk.Frame(self.tab_overview)
        info_frame.pack(fill=tk.X, padx=10, pady=5)

        self.lbl_subject = ttk.Label(info_frame, text="Subject: ")
        self.lbl_subject.pack(anchor=tk.W)
        self.lbl_sender = ttk.Label(info_frame, text="Sender: ")
        self.lbl_sender.pack(anchor=tk.W)

        # Actions
        actions_frame = ttk.Frame(self.tab_overview)
        actions_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(actions_frame, text="Export JSON Report", command=lambda: self._export('json')).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Export HTML Report", command=lambda: self._export('html')).pack(side=tk.LEFT, padx=5)
        ttk.Button(actions_frame, text="Export TXT Report", command=lambda: self._export('txt')).pack(side=tk.LEFT, padx=5)

    def _build_headers_tab(self):
        self.tab_headers = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_headers, text="Headers / هدرها")

        self.txt_headers = tk.Text(self.tab_headers, bg=ModernTheme.TEXT_BG, fg=ModernTheme.FG, font=('Consolas', 10))
        self.txt_headers.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def _build_spf_tab(self):
        self.tab_spf = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_spf, text="SPF & DMARC / بررسی اصالت")

        # Split into top (summary) and bottom (trace)
        top_frame = ttk.Frame(self.tab_spf)
        top_frame.pack(fill=tk.X, padx=10, pady=10)

        # Summary left
        summary_frame = ttk.LabelFrame(top_frame, text="Identities & DMARC")
        summary_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        self.lbl_spf_from = ttk.Label(summary_frame, text="Visible From: ")
        self.lbl_spf_from.pack(anchor=tk.W, padx=5, pady=2)

        self.lbl_spf_env = ttk.Label(summary_frame, text="Env Sender: ")
        self.lbl_spf_env.pack(anchor=tk.W, padx=5, pady=2)

        self.lbl_spf_ip = ttk.Label(summary_frame, text="Client IP: ")
        self.lbl_spf_ip.pack(anchor=tk.W, padx=5, pady=2)

        self.lbl_spf_ip_src = ttk.Label(summary_frame, text="IP Source: ")
        self.lbl_spf_ip_src.pack(anchor=tk.W, padx=5, pady=2)

        # Manual IP override
        manual_frame = ttk.Frame(summary_frame)
        manual_frame.pack(fill=tk.X, padx=5, pady=2)
        ttk.Label(manual_frame, text="Manual IP Override:").pack(side=tk.LEFT)
        self.entry_manual_ip = ttk.Entry(manual_frame, width=15)
        self.entry_manual_ip.pack(side=tk.LEFT, padx=5)
        ttk.Button(manual_frame, text="Re-evaluate", command=self._reevaluate_spf).pack(side=tk.LEFT)

        ttk.Separator(summary_frame, orient='horizontal').pack(fill=tk.X, pady=5)

        self.lbl_dmarc_res = ttk.Label(summary_frame, text="DMARC Result: ")
        self.lbl_dmarc_res.pack(anchor=tk.W, padx=5, pady=2)

        self.lbl_dmarc_align = ttk.Label(summary_frame, text="SPF Alignment: ")
        self.lbl_dmarc_align.pack(anchor=tk.W, padx=5, pady=2)

        self.lbl_dkim_align = ttk.Label(summary_frame, text="DKIM Alignment: ")
        self.lbl_dkim_align.pack(anchor=tk.W, padx=5, pady=2)

        # Summary right
        eval_frame = ttk.LabelFrame(top_frame, text="Evaluations")
        eval_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(5, 0))

        self.lbl_eval_orig = ttk.Label(eval_frame, text="Original SPF (Env Sender): ")
        self.lbl_eval_orig.pack(anchor=tk.W, padx=5, pady=2)

        self.lbl_eval_orig_exp = ttk.Label(eval_frame, text="", foreground=ModernTheme.WARN)
        self.lbl_eval_orig_exp.pack(anchor=tk.W, padx=5, pady=2)

        ttk.Separator(eval_frame, orient='horizontal').pack(fill=tk.X, pady=5)

        self.lbl_eval_from = ttk.Label(eval_frame, text="From Domain SPF: ")
        self.lbl_eval_from.pack(anchor=tk.W, padx=5, pady=2)

        self.lbl_eval_from_exp = ttk.Label(eval_frame, text="", foreground=ModernTheme.WARN)
        self.lbl_eval_from_exp.pack(anchor=tk.W, padx=5, pady=2)

        # Trace
        trace_frame = ttk.LabelFrame(self.tab_spf, text="Authorization Trace (From Domain Policy)")
        trace_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        columns = ("Domain", "Mechanism", "Result", "Reason")
        self.tree_spf_trace = ttk.Treeview(trace_frame, columns=columns, show="headings")
        self.tree_spf_trace.heading("Domain", text="Domain")
        self.tree_spf_trace.heading("Mechanism", text="Mechanism")
        self.tree_spf_trace.heading("Result", text="Result")
        self.tree_spf_trace.heading("Reason", text="Reason")

        self.tree_spf_trace.column("Domain", width=150)
        self.tree_spf_trace.column("Mechanism", width=100)
        self.tree_spf_trace.column("Result", width=80)
        self.tree_spf_trace.column("Reason", width=400)

        self.tree_spf_trace.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def _build_findings_tab(self):
        self.tab_findings = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_findings, text="Findings / یافته‌ها")

        columns = ("Severity", "Category", "Evidence", "Action")
        self.tree_findings = ttk.Treeview(self.tab_findings, columns=columns, show="headings")
        self.tree_findings.heading("Severity", text="Severity")
        self.tree_findings.heading("Category", text="Category")
        self.tree_findings.heading("Evidence", text="Evidence")
        self.tree_findings.heading("Action", text="Action")

        self.tree_findings.column("Severity", width=100)
        self.tree_findings.column("Category", width=150)
        self.tree_findings.column("Evidence", width=300)
        self.tree_findings.column("Action", width=250)

        self.tree_findings.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

    def _build_urls_tab(self):
        self.tab_urls = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_urls, text="URLs / لینک‌ها")

        columns = ("Domain", "Defanged URL")
        self.tree_urls = ttk.Treeview(self.tab_urls, columns=columns, show="headings")
        self.tree_urls.heading("Domain", text="Domain")
        self.tree_urls.heading("Defanged URL", text="Defanged URL")
        self.tree_urls.column("Domain", width=200)

        self.tree_urls.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Context menu for VT lookup
        self.url_menu = tk.Menu(self, tearoff=0, bg=ModernTheme.PANEL_BG, fg=ModernTheme.FG)
        self.url_menu.add_command(label="Copy URL", command=self._copy_url)
        # We don't query URLs to VT directly without user consent, add option
        self.tree_urls.bind("<Button-3>", self._show_url_menu)

    def _build_attachments_tab(self):
        self.tab_attachments = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_attachments, text="Attachments / پیوست‌ها")

        columns = ("Filename", "Size", "SHA256")
        self.tree_attachments = ttk.Treeview(self.tab_attachments, columns=columns, show="headings")
        self.tree_attachments.heading("Filename", text="Filename")
        self.tree_attachments.heading("Size", text="Size (Bytes)")
        self.tree_attachments.heading("SHA256", text="SHA-256 Hash")

        self.tree_attachments.column("Size", width=100)
        self.tree_attachments.column("SHA256", width=400)

        self.tree_attachments.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        self.att_menu = tk.Menu(self, tearoff=0, bg=ModernTheme.PANEL_BG, fg=ModernTheme.FG)
        self.att_menu.add_command(label="Copy Hash", command=self._copy_hash)
        self.att_menu.add_command(label="Lookup Hash on VirusTotal", command=self._lookup_hash_vt)
        self.att_menu.add_command(label="Save to Quarantine", command=self._save_attachment)
        self.tree_attachments.bind("<Button-3>", self._show_att_menu)

    def _build_history_tab(self):
        self.tab_history = ttk.Frame(self.notebook)
        self.notebook.add(self.tab_history, text="History / تاریخچه")

        columns = ("Date", "Subject", "Score", "Severity")
        self.tree_history = ttk.Treeview(self.tab_history, columns=columns, show="headings")
        self.tree_history.heading("Date", text="Date")
        self.tree_history.heading("Subject", text="Subject")
        self.tree_history.heading("Score", text="Risk Score")
        self.tree_history.heading("Severity", text="Severity")

        self.tree_history.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        btn_refresh = ttk.Button(self.tab_history, text="Refresh History", command=self._load_history)
        btn_refresh.pack(pady=5)

        self._load_history()

    # --- Actions ---

    def _open_file(self):
        filepath = filedialog.askopenfilename(filetypes=[("Email files", "*.eml"), ("All files", "*.*")])
        if filepath:
            self._clear_all()
            self.status_label.config(text="Analyzing...")
            self.progress_var.set(20)

            # Run in thread
            threading.Thread(target=self._analyze_file_thread, args=(filepath,), daemon=True).start()

    def _analyze_file_thread(self, filepath):
        try:
            results = self.parser.parse_file(filepath)
            self.progress_var.set(80)

            # Save to DB
            self.db.save_analysis(
                results['subject'], results['sender'], results['score'],
                results['severity'], results['findings'], results['headers']
            )

            self.after(0, self._update_ui_with_results, results)
        except Exception as e:
            self.after(0, self._show_error, f"Analysis failed: {str(e)}")

    def _update_ui_with_results(self, results):
        self.current_analysis = results

        # Overview
        self.lbl_score.config(text=f"Risk Score: {results['score']}")

        color = ModernTheme.FG
        if results['severity'] == 'Critical': color = ModernTheme.ERROR
        elif results['severity'] == 'High': color = "#fd7e14"
        elif results['severity'] == 'Medium': color = ModernTheme.WARN

        self.lbl_score.config(foreground=color)
        self.lbl_severity.config(text=f"Severity: {results['severity']}", foreground=color)

        self.lbl_subject.config(text=f"Subject: {results['subject']}")
        self.lbl_sender.config(text=f"Sender: {results['sender']}")

        # Headers
        self.txt_headers.insert(tk.END, json.dumps(results['headers'], indent=4))

        # SPF Investigation
        spf = results.get('spf_investigation', {})
        self.lbl_spf_from.config(text=f"Visible From: {spf.get('visible_from_domain', 'N/A')}")
        self.lbl_spf_env.config(text=f"Env Sender: {spf.get('envelope_sender_domain', 'N/A')}")
        self.lbl_spf_ip.config(text=f"Client IP: {spf.get('client_ip', 'N/A')}")
        self.lbl_spf_ip_src.config(text=f"IP Source: {spf.get('client_ip_source', 'N/A')}")

        dmarc = spf.get('dmarc', {})
        self.lbl_dmarc_res.config(text=f"DMARC Result: {dmarc.get('overall_result', 'N/A')} (Policy: {dmarc.get('policy', 'N/A')})")
        self.lbl_dmarc_align.config(text=f"SPF Alignment: {dmarc.get('spf_alignment', 'N/A')}")
        self.lbl_dkim_align.config(text=f"DKIM Alignment: {dmarc.get('dkim_alignment', 'N/A')}")

        inv = spf.get('investigations', {})
        orig_auth = inv.get('original_auth', {})
        self.lbl_eval_orig.config(text=f"Original SPF ({orig_auth.get('evaluated_domain', 'N/A')}): {orig_auth.get('result', 'N/A')}")
        self.lbl_eval_orig_exp.config(text=orig_auth.get('explanation', ''))

        from_auth = inv.get('visible_from_auth', {})
        self.lbl_eval_from.config(text=f"From Domain SPF ({from_auth.get('evaluated_domain', 'N/A')}): {from_auth.get('result', 'N/A')}")
        self.lbl_eval_from_exp.config(text=from_auth.get('explanation', ''))

        for item in self.tree_spf_trace.get_children(): self.tree_spf_trace.delete(item)
        for trace_item in from_auth.get('trace', []):
            self.tree_spf_trace.insert("", tk.END, values=(
                trace_item.get('domain'), trace_item.get('mechanism'),
                trace_item.get('result'), trace_item.get('reason')
            ))

        # Findings
        for finding in results['findings']:
            self.tree_findings.insert("", tk.END, values=(
                finding.get('severity'), finding.get('category'),
                finding.get('evidence'), finding.get('action')
            ))

        # URLs
        for url in results['urls']:
            self.tree_urls.insert("", tk.END, values=(url.get('domain'), url.get('defanged')))

        # Attachments
        for att in results['attachments']:
            self.tree_attachments.insert("", tk.END, values=(
                att.get('filename'), att.get('size'), att.get('sha256')
            ))

        self.progress_var.set(100)
        self.status_label.config(text="Analysis Complete / پایان تحلیل")
        self._load_history()

    def _clear_all(self):
        self.current_analysis = None
        self.lbl_score.config(text="Risk Score: N/A", foreground=ModernTheme.FG)
        self.lbl_severity.config(text="Severity: N/A", foreground=ModernTheme.FG)
        self.lbl_subject.config(text="Subject: ")
        self.lbl_sender.config(text="Sender: ")

        self.txt_headers.delete(1.0, tk.END)

        self.lbl_spf_from.config(text="Visible From: ")
        self.lbl_spf_env.config(text="Env Sender: ")
        self.lbl_spf_ip.config(text="Client IP: ")
        self.lbl_spf_ip_src.config(text="IP Source: ")
        self.lbl_dmarc_res.config(text="DMARC Result: ")
        self.lbl_dmarc_align.config(text="SPF Alignment: ")
        self.lbl_dkim_align.config(text="DKIM Alignment: ")
        self.lbl_eval_orig.config(text="Original SPF: ")
        self.lbl_eval_orig_exp.config(text="")
        self.lbl_eval_from.config(text="From Domain SPF: ")
        self.lbl_eval_from_exp.config(text="")
        for item in self.tree_spf_trace.get_children(): self.tree_spf_trace.delete(item)

        for item in self.tree_findings.get_children(): self.tree_findings.delete(item)
        for item in self.tree_urls.get_children(): self.tree_urls.delete(item)
        for item in self.tree_attachments.get_children(): self.tree_attachments.delete(item)

        self.progress_var.set(0)
        self.status_label.config(text="Ready / آماده")

    def _show_error(self, message):
        self.status_label.config(text="Error")
        self.progress_var.set(0)
        messagebox.showerror("Error", message)

    def _export(self, format_type):
        if not self.current_analysis:
            messagebox.showwarning("Warning", "No analysis to export.")
            return

        filename = f"report_{self.current_analysis['score']}_{format_type}.{format_type}"
        filepath = filedialog.asksaveasfilename(defaultextension=f".{format_type}", initialfile=filename)

        if filepath:
            try:
                if format_type == 'json':
                    self.exporter.export_json(self.current_analysis, filepath)
                elif format_type == 'txt':
                    self.exporter.export_txt(self.current_analysis, filepath)
                elif format_type == 'html':
                    self.exporter.export_html(self.current_analysis, filepath)
                messagebox.showinfo("Success", f"Report saved to {filepath}")
            except Exception as e:
                self._show_error(f"Export failed: {str(e)}")

    def _load_history(self):
        for item in self.tree_history.get_children():
            self.tree_history.delete(item)
        history = self.db.get_history()
        for record in history:
            self.tree_history.insert("", tk.END, values=(
                record['timestamp'][:19].replace('T', ' '),
                record['subject'], record['risk_score'], record['severity']
            ))

    # --- Context Menus ---

    def _show_url_menu(self, event):
        item = self.tree_urls.identify_row(event.y)
        if item:
            self.tree_urls.selection_set(item)
            self.url_menu.post(event.x_root, event.y_root)

    def _copy_url(self):
        selected = self.tree_urls.selection()
        if selected:
            item = self.tree_urls.item(selected[0])
            url = item['values'][1] # defanged URL
            self.clipboard_clear()
            self.clipboard_append(url)

    def _show_att_menu(self, event):
        item = self.tree_attachments.identify_row(event.y)
        if item:
            self.tree_attachments.selection_set(item)
            self.att_menu.post(event.x_root, event.y_root)

    def _copy_hash(self):
        selected = self.tree_attachments.selection()
        if selected:
            item = self.tree_attachments.item(selected[0])
            h = item['values'][2] # SHA256
            self.clipboard_clear()
            self.clipboard_append(h)

    def _save_attachment(self):
        selected = self.tree_attachments.selection()
        if not selected or not self.current_analysis:
            return

        item = self.tree_attachments.item(selected[0])
        filename = item['values'][0]
        sha256 = item['values'][2]

        # Find the actual payload
        payload = None
        for att in self.current_analysis['attachments']:
            if att['sha256'] == sha256 and att['filename'] == filename:
                payload = att.get('payload')
                break

        if not payload:
            messagebox.showerror("Error", "Attachment payload not found in memory.")
            return

        quarantine_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'quarantine')
        os.makedirs(quarantine_dir, exist_ok=True)

        safe_filename = f"quarantine_{sha256[:10]}_{filename}.bin"
        save_path = os.path.join(quarantine_dir, safe_filename)

        try:
            with open(save_path, 'wb') as f:
                f.write(payload)
            messagebox.showinfo("Quarantined", f"Saved safely to:\n{save_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save attachment: {e}")

    def _lookup_hash_vt(self):
        selected = self.tree_attachments.selection()
        if selected:
            item = self.tree_attachments.item(selected[0])
            h = item['values'][2]

            if not self.ti.api_keys.get('virustotal'):
                messagebox.showinfo("Info", "VirusTotal API key is not configured. Please add it in settings.")
                return

            if messagebox.askyesno("Confirm Lookup", f"Submit hash {h[:8]}... to VirusTotal?"):
                self.status_label.config(text="Querying VT...")
                threading.Thread(target=self._vt_lookup_thread, args=(h,), daemon=True).start()

    def _reevaluate_spf(self):
        if not self.current_analysis:
            return

        manual_ip = self.entry_manual_ip.get().strip()
        if not manual_ip:
            messagebox.showwarning("Input Required", "Please enter an IP address.")
            return

        # Re-run SPF investigation with the manual IP in a thread
        self.status_label.config(text="Re-evaluating SPF...")
        threading.Thread(target=self._reevaluate_spf_thread, args=(manual_ip,), daemon=True).start()

    def _reevaluate_spf_thread(self, manual_ip):
        try:
            # We reconstruct the parts needed by the investigator
            msg = None # Ideally we'd keep the parsed email object around, but we can mock enough for investigate
            # Or better, we can modify the investigator to accept an explicit IP override
            # Since the investigator takes a `msg` primarily to extract the IP, we can temporarily modify the headers
            # or pass the override IP.
            from email.message import EmailMessage
            fake_msg = EmailMessage()
            fake_msg.add_header('Received', f'from manual ({manual_ip})')

            new_spf_report = self.parser.spf_investigator.investigate(
                fake_msg,
                self.current_analysis['headers'],
                self.current_analysis['auth']
            )

            # Label as manual
            new_spf_report['client_ip_source'] = "Manual Override (What-If)"

            self.after(0, self._update_spf_ui, new_spf_report)
        except Exception as e:
            self.after(0, self._show_error, f"SPF Re-evaluation failed: {str(e)}")

    def _update_spf_ui(self, spf):
        self.status_label.config(text="Ready / آماده")
        self.lbl_spf_from.config(text=f"Visible From: {spf.get('visible_from_domain', 'N/A')}")
        self.lbl_spf_env.config(text=f"Env Sender: {spf.get('envelope_sender_domain', 'N/A')}")
        self.lbl_spf_ip.config(text=f"Client IP: {spf.get('client_ip', 'N/A')}")
        self.lbl_spf_ip_src.config(text=f"IP Source: {spf.get('client_ip_source', 'N/A')}")

        dmarc = spf.get('dmarc', {})
        self.lbl_dmarc_res.config(text=f"DMARC Result: {dmarc.get('overall_result', 'N/A')} (Policy: {dmarc.get('policy', 'N/A')})")
        self.lbl_dmarc_align.config(text=f"SPF Alignment: {dmarc.get('spf_alignment', 'N/A')}")
        self.lbl_dkim_align.config(text=f"DKIM Alignment: {dmarc.get('dkim_alignment', 'N/A')}")

        inv = spf.get('investigations', {})
        orig_auth = inv.get('original_auth', {})
        self.lbl_eval_orig.config(text=f"Original SPF ({orig_auth.get('evaluated_domain', 'N/A')}): {orig_auth.get('result', 'N/A')}")
        self.lbl_eval_orig_exp.config(text=orig_auth.get('explanation', ''))

        from_auth = inv.get('visible_from_auth', {})
        self.lbl_eval_from.config(text=f"From Domain SPF ({from_auth.get('evaluated_domain', 'N/A')}): {from_auth.get('result', 'N/A')}")
        self.lbl_eval_from_exp.config(text=from_auth.get('explanation', ''))

        for item in self.tree_spf_trace.get_children(): self.tree_spf_trace.delete(item)
        for trace_item in from_auth.get('trace', []):
            self.tree_spf_trace.insert("", tk.END, values=(
                trace_item.get('domain'), trace_item.get('mechanism'),
                trace_item.get('result'), trace_item.get('reason')
            ))

    def _vt_lookup_thread(self, h):
        res = self.ti.lookup_hash_vt(h)
        self.after(0, self._handle_vt_result, res)

    def _handle_vt_result(self, res):
        self.status_label.config(text="Ready / آماده")
        if res.get('status') == 'success':
            if 'malicious' in res:
                msg = f"VirusTotal Result: {res['malicious']} / {res['total']} engines detected this as malicious.\nLink: {res['link']}"
            else:
                msg = f"VirusTotal Result: {res.get('message', 'Not found')}"
            messagebox.showinfo("Threat Intel", msg)
        else:
            messagebox.showerror("Threat Intel Error", res.get('message', 'Unknown error'))

    def _open_ti_settings(self):
        settings_win = tk.Toplevel(self)
        settings_win.title("Threat Intelligence Settings")
        settings_win.geometry("400x200")
        settings_win.configure(bg=ModernTheme.BG)

        ttk.Label(settings_win, text="VirusTotal API Key:").pack(pady=5)
        vt_entry = ttk.Entry(settings_win, width=40)
        vt_entry.insert(0, self.ti.api_keys.get('virustotal', ''))
        vt_entry.pack(pady=5)

        ttk.Label(settings_win, text="URLhaus API Key (Optional):").pack(pady=5)
        url_entry = ttk.Entry(settings_win, width=40)
        url_entry.insert(0, self.ti.api_keys.get('urlhaus', ''))
        url_entry.pack(pady=5)

        def save():
            self.ti.save_config(vt_entry.get(), url_entry.get())
            settings_win.destroy()
            messagebox.showinfo("Success", "Settings saved locally.")

        ttk.Button(settings_win, text="Save", command=save).pack(pady=10)
