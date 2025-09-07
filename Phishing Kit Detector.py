import requests
import re
import os
import json
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from urllib.parse import urlparse, urljoin, quote
import whois
from bs4 import BeautifulSoup
import threading
import time
import sqlite3
from datetime import datetime
import hashlib

class PhishingKitDetector:
    def __init__(self):
        self.phishing_indicators = {
            'url_patterns': [
                r'login\.\w+\.\w+',  # Subdomain with login
                r'\w+-login\.\w+',   # Hyphenated login domains
                r'secure-?\.\w+',    # Fake secure subdomains
                r'verify-?\.\w+',    # Verification subdomains
                r'account-?\.\w+',   # Account subdomains
                r'auth-?\.\w+',      # Authentication subdomains
                r'\d+\.\d+\.\d+\.\d+',  # IP address in domain
                r'\.(tk|ml|ga|cf|gq)$',  # Free domains often used for phishing
            ],
            'content_patterns': [
                r'login|signin|auth|authenticate|verify|validation|security|account',
                r'password|credential|username|email|account',
                r'bank|paypal|ebay|amazon|google|facebook|microsoft|apple',
                r'update|confirm|verify|validate|secure',
                r'urgent|immediate|action required|suspended|locked',
            ],
            'html_patterns': [
                r'<form.*action=.*login',
                r'<input.*type=.*password',
                r'<input.*name=.*password',
                r'<input.*name=.*user',
                r'<input.*name=.*email',
                r'<meta.*name=.*description.*content=.*login',
            ],
            'js_patterns': [
                r'password|login|auth',
                r'document\.cookie',
                r'window\.location',
                r'\.php\?.*=.*',
                r'eval\(|Function\(\)',
            ]
        }

        self.known_phishing_signatures = {
            'file_paths': [
                '/admin/', '/cp/', '/panel/', '/config/', '/database/',
                '/php/login.php', '/wp-admin/', '/vendor/', '/includes/',
                '/images/logo.png', '/css/login.css', '/js/validate.js'
            ],
            'file_names': [
                'config.php', 'database.php', 'login.php', 'auth.php',
                'admin.php', 'connect.php', 'mail.php', 'send.php',
                'credentials.txt', 'passwords.txt', 'users.txt'
            ],
            'content_signatures': [
                'phishing', 'kit', 'hack', 'bypass', 'exploit',
                'undetectable', 'stealer', 'logger', 'keylogger',
                'banker', 'creditcard', 'cvv', 'fullz'
            ]
        }

        self.suspicious_keywords = [
            'login', 'signin', 'password', 'bank', 'paypal', 'ebay',
            'amazon', 'google', 'facebook', 'microsoft', 'apple',
            'verify', 'confirm', 'update', 'security', 'account',
            'urgent', 'immediate', 'suspended', 'locked'
        ]

        self.results = {
            'phishing_score': 0,
            'indicators_found': [],
            'suspicious_elements': [],
            'recommendations': [],
            'analysis_details': {}
        }

    def analyze_url(self, url):
        """Analyze URL for phishing indicators"""
        analysis = {
            'url_analysis': self._analyze_url_structure(url),
            'content_analysis': {},
            'technical_analysis': {},
            'reputation_analysis': {}
        }

        try:
            # Get website content
            response = self._get_website_content(url)
            if response:
                analysis['content_analysis'] = self._analyze_content(response.text, response.headers)
                analysis['technical_analysis'] = self._analyze_technical_aspects(response, url)
                analysis['reputation_analysis'] = self._analyze_reputation(url)
            
            # Calculate overall phishing score
            analysis['phishing_score'] = self._calculate_phishing_score(analysis)
            
        except Exception as e:
            analysis['error'] = str(e)
        
        return analysis

    def _analyze_url_structure(self, url):
        """Analyze URL structure for phishing indicators"""
        analysis = {'indicators': [], 'score': 0}
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        
        # Check domain patterns
        for pattern in self.phishing_indicators['url_patterns']:
            if re.search(pattern, domain, re.IGNORECASE):
                analysis['indicators'].append(f"Suspicious domain pattern: {pattern}")
                analysis['score'] += 10
        
        # Check for IP address in domain
        if re.search(r'\d+\.\d+\.\d+\.\d+', domain):
            analysis['indicators'].append("IP address used in domain (suspicious)")
            analysis['score'] += 15
        
        # Check for free TLDs
        if re.search(r'\.(tk|ml|ga|cf|gq)$', domain):
            analysis['indicators'].append("Free domain TLD (often used for phishing)")
            analysis['score'] += 12
        
        # Check URL length
        if len(url) > 75:
            analysis['indicators'].append("Long URL (may be hiding real domain)")
            analysis['score'] += 8
        
        return analysis

    def _get_website_content(self, url):
        """Get website content with proper headers"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5',
                'Connection': 'keep-alive',
            }
            
            response = requests.get(url, headers=headers, timeout=15, allow_redirects=True)
            return response
            
        except requests.RequestException as e:
            print(f"Error fetching website: {e}")
            return None

    def _analyze_content(self, html_content, headers):
        """Analyze website content for phishing indicators"""
        analysis = {'indicators': [], 'score': 0, 'suspicious_elements': []}
        soup = BeautifulSoup(html_content, 'html.parser')
        
        # Check title
        title = soup.find('title')
        if title:
            title_text = title.get_text().lower()
            for keyword in self.suspicious_keywords:
                if keyword in title_text:
                    analysis['indicators'].append(f"Suspicious title keyword: {keyword}")
                    analysis['score'] += 5
        
        # Check meta description
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        if meta_desc and meta_desc.get('content'):
            desc = meta_desc['content'].lower()
            for keyword in self.suspicious_keywords:
                if keyword in desc:
                    analysis['indicators'].append(f"Suspicious meta description keyword: {keyword}")
                    analysis['score'] += 4
        
        # Check forms
        forms = soup.find_all('form')
        for form in forms:
            form_action = form.get('action', '').lower()
            form_html = str(form).lower()
            
            # Check for password fields
            if 'password' in form_html or 'type="password"' in form_html:
                analysis['indicators'].append("Password input field detected")
                analysis['score'] += 8
            
            # Check for suspicious action URLs
            if any(x in form_action for x in ['login', 'auth', 'verify']):
                analysis['indicators'].append(f"Suspicious form action: {form_action}")
                analysis['score'] += 6
        
        # Check for hidden elements
        hidden_inputs = soup.find_all('input', type='hidden')
        if len(hidden_inputs) > 5:  # More than 5 hidden inputs is suspicious
            analysis['indicators'].append("Multiple hidden input fields detected")
            analysis['score'] += 5
        
        # Check for external resources
        external_resources = 0
        for tag in soup.find_all(['img', 'script', 'link']):
            src = tag.get('src', '') or tag.get('href', '')
            if src and not src.startswith(('data:', 'about:')):
                parsed_src = urlparse(src)
                if parsed_src.netloc:  # External resource
                    external_resources += 1
        
        if external_resources > 10:
            analysis['indicators'].append("Many external resources (could be loading phishing content)")
            analysis['score'] += 7
        
        return analysis

    def _analyze_technical_aspects(self, response, url):
        """Analyze technical aspects of the website"""
        analysis = {'indicators': [], 'score': 0}
        
        # Check SSL/TLS
        if response.url.startswith('http://'):
            analysis['indicators'].append("No HTTPS (insecure connection)")
            analysis['score'] += 10
        
        # Check headers
        headers = response.headers
        security_headers = ['X-Frame-Options', 'X-Content-Type-Options', 'Content-Security-Policy']
        missing_headers = [h for h in security_headers if h not in headers]
        
        if missing_headers:
            analysis['indicators'].append(f"Missing security headers: {', '.join(missing_headers)}")
            analysis['score'] += 3 * len(missing_headers)
        
        # Check server headers
        server = headers.get('Server', '').lower()
        if any(x in server for x in ['apache', 'nginx', 'iis']):
            analysis['indicators'].append("Standard server header (normal)")
        else:
            analysis['indicators'].append(f"Unusual server header: {server}")
            analysis['score'] += 5
        
        return analysis

    def _analyze_reputation(self, url):
        """Analyze domain reputation"""
        analysis = {'indicators': [], 'score': 0}
        parsed = urlparse(url)
        domain = parsed.netloc
        
        try:
            # WHOIS lookup
            domain_info = whois.whois(domain)
            
            # Check domain age
            if domain_info.creation_date:
                if isinstance(domain_info.creation_date, list):
                    creation_date = domain_info.creation_date[0]
                else:
                    creation_date = domain_info.creation_date
                
                domain_age = (datetime.now() - creation_date).days
                if domain_age < 30:  # Less than 30 days old
                    analysis['indicators'].append(f"New domain ({domain_age} days old)")
                    analysis['score'] += 15
            
            # Check registrar
            registrar = domain_info.registrar or ''
            if any(x in registrar.lower() for x in ['free', 'cheap', 'discount']):
                analysis['indicators'].append(f"Suspicious registrar: {registrar}")
                analysis['score'] += 8
                
        except Exception:
            analysis['indicators'].append("WHOIS lookup failed (domain may be hiding information)")
            analysis['score'] += 10
        
        return analysis

    def _calculate_phishing_score(self, analysis):
        """Calculate overall phishing probability score"""
        total_score = 0
        total_score += analysis['url_analysis']['score'] * 0.3
        total_score += analysis['content_analysis']['score'] * 0.4
        total_score += analysis['technical_analysis']['score'] * 0.2
        total_score += analysis['reputation_analysis']['score'] * 0.1
        
        return min(100, int(total_score))

    def scan_directory(self, directory_path):
        """Scan directory for known phishing kit files"""
        results = {
            'suspicious_files': [],
            'phishing_indicators': [],
            'total_files_scanned': 0,
            'malicious_files_found': 0
        }
        
        try:
            for root, dirs, files in os.walk(directory_path):
                for file in files:
                    results['total_files_scanned'] += 1
                    file_path = os.path.join(root, file)
                    
                    # Check file path patterns
                    rel_path = os.path.relpath(file_path, directory_path)
                    for pattern in self.known_phishing_signatures['file_paths']:
                        if pattern in rel_path.replace('\\', '/'):
                            results['suspicious_files'].append({
                                'file': rel_path,
                                'reason': f'Matches known phishing path pattern: {pattern}',
                                'severity': 'high'
                            })
                            results['malicious_files_found'] += 1
                    
                    # Check file names
                    for suspicious_name in self.known_phishing_signatures['file_names']:
                        if file.lower() == suspicious_name:
                            results['suspicious_files'].append({
                                'file': rel_path,
                                'reason': f'Known phishing file name: {suspicious_name}',
                                'severity': 'high'
                            })
                            results['malicious_files_found'] += 1
                    
                    # Check file content for certain extensions
                    if file.endswith(('.php', '.js', '.html', '.txt')):
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read().lower()
                                
                                for signature in self.known_phishing_signatures['content_signatures']:
                                    if signature in content:
                                        results['suspicious_files'].append({
                                            'file': rel_path,
                                            'reason': f'Contains phishing signature: {signature}',
                                            'severity': 'critical'
                                        })
                                        results['malicious_files_found'] += 1
                                        break
                                
                                # Check for encoded content
                                if 'base64_decode' in content or 'eval(' in content:
                                    results['suspicious_files'].append({
                                        'file': rel_path,
                                        'reason': 'Contains encoded/obfuscated content',
                                        'severity': 'medium'
                                    })
                                    results['malicious_files_found'] += 1
                                    
                        except UnicodeDecodeError:
                            # Skip binary files
                            continue
            
        except Exception as e:
            results['error'] = str(e)
        
        return results


class PhishingKitDetectorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Phishing Kit Detector")
        self.root.geometry("1000x700")
        
        self.detector = PhishingKitDetector()
        self.current_results = None
        
        # Create main notebook
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # URL Analysis tab
        self.url_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.url_tab, text="URL Analysis")
        
        # File Analysis tab
        self.file_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.file_tab, text="File Analysis")
        
        # Results tab
        self.results_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.results_tab, text="Analysis Results")
        
        self.setup_url_tab()
        self.setup_file_tab()
        self.setup_results_tab()
        
    def setup_url_tab(self):
        """Setup URL analysis tab"""
        frame = ttk.Frame(self.url_tab, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        # URL input
        ttk.Label(frame, text="Enter URL to analyze:", font=('Arial', 11)).pack(anchor=tk.W, pady=5)
        
        url_frame = ttk.Frame(frame)
        url_frame.pack(fill=tk.X, pady=5)
        
        self.url_entry = ttk.Entry(url_frame, font=('Arial', 10))
        self.url_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        self.url_entry.insert(0, "https://")
        
        ttk.Button(url_frame, text="Analyze", command=self.analyze_url).pack(side=tk.RIGHT)
        
        # Quick scan options
        options_frame = ttk.LabelFrame(frame, text="Scan Options", padding="5")
        options_frame.pack(fill=tk.X, pady=10)
        
        self.deep_scan_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Deep Scan (more thorough)", variable=self.deep_scan_var).pack(anchor=tk.W)
        
        self.check_reputation_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Check Domain Reputation", variable=self.check_reputation_var).pack(anchor=tk.W)
        
        # Status
        self.status_var = tk.StringVar()
        self.status_var.set("Ready to analyze")
        ttk.Label(frame, textvariable=self.status_var).pack(anchor=tk.W, pady=5)
        
    def setup_file_tab(self):
        """Setup file analysis tab"""
        frame = ttk.Frame(self.file_tab, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Scan directory for phishing kit files:", font=('Arial', 11)).pack(anchor=tk.W, pady=5)
        
        # Directory selection
        dir_frame = ttk.Frame(frame)
        dir_frame.pack(fill=tk.X, pady=5)
        
        self.dir_entry = ttk.Entry(dir_frame, font=('Arial', 10))
        self.dir_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        ttk.Button(dir_frame, text="Browse", command=self.browse_directory).pack(side=tk.RIGHT)
        ttk.Button(dir_frame, text="Scan", command=self.scan_directory).pack(side=tk.RIGHT, padx=(5, 0))
        
        # File scan options
        options_frame = ttk.LabelFrame(frame, text="File Scan Options", padding="5")
        options_frame.pack(fill=tk.X, pady=10)
        
        self.scan_content_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options_frame, text="Scan File Contents", variable=self.scan_content_var).pack(anchor=tk.W)
        
        self.quick_scan_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(options_frame, text="Quick Scan (file names only)", variable=self.quick_scan_var).pack(anchor=tk.W)
        
    def setup_results_tab(self):
        """Setup results tab"""
        notebook = ttk.Notebook(self.results_tab)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Summary tab
        summary_tab = ttk.Frame(notebook)
        notebook.add(summary_tab, text="Summary")
        
        self.summary_text = scrolledtext.ScrolledText(summary_tab, wrap=tk.WORD)
        self.summary_text.pack(fill=tk.BOTH, expand=True)
        
        # Details tab
        details_tab = ttk.Frame(notebook)
        notebook.add(details_tab, text="Details")
        
        # Treeview for detailed results
        columns = ('type', 'severity', 'description', 'details')
        self.results_tree = ttk.Treeview(details_tab, columns=columns, show='headings', height=20)
        
        self.results_tree.heading('type', text='Type')
        self.results_tree.heading('severity', text='Severity')
        self.results_tree.heading('description', text='Description')
        self.results_tree.heading('details', text='Details')
        
        self.results_tree.column('type', width=100)
        self.results_tree.column('severity', width=80)
        self.results_tree.column('description', width=250)
        self.results_tree.column('details', width=300)
        
        self.results_tree.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(details_tab, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Actions frame
        actions_frame = ttk.Frame(self.results_tab)
        actions_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(actions_frame, text="Export Report", command=self.export_report).pack(side=tk.LEFT)
        ttk.Button(actions_frame, text="Clear Results", command=self.clear_results).pack(side=tk.LEFT, padx=5)
        
    def analyze_url(self):
        """Analyze URL for phishing indicators"""
        url = self.url_entry.get().strip()
        if not url or url == "https://":
            messagebox.showerror("Error", "Please enter a valid URL")
            return
        
        self.status_var.set("Analyzing URL...")
        
        def analysis_thread():
            try:
                results = self.detector.analyze_url(url)
                self.root.after(0, self.display_url_results, results, url)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Analysis failed: {str(e)}"))
                self.root.after(0, lambda: self.status_var.set("Analysis failed"))
        
        threading.Thread(target=analysis_thread, daemon=True).start()
    
    def scan_directory(self):
        """Scan directory for phishing kit files"""
        directory = self.dir_entry.get().strip()
        if not directory or not os.path.isdir(directory):
            messagebox.showerror("Error", "Please select a valid directory")
            return
        
        self.status_var.set("Scanning directory...")
        
        def scan_thread():
            try:
                results = self.detector.scan_directory(directory)
                self.root.after(0, self.display_file_results, results, directory)
            except Exception as e:
                self.root.after(0, lambda: messagebox.showerror("Error", f"Scan failed: {str(e)}"))
                self.root.after(0, lambda: self.status_var.set("Scan failed"))
        
        threading.Thread(target=scan_thread, daemon=True).start()
    
    def display_url_results(self, results, url):
        """Display URL analysis results"""
        self.current_results = results
        
        # Clear previous results
        self.summary_text.delete(1.0, tk.END)
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Display summary
        score = results.get('phishing_score', 0)
        risk_level = "LOW" if score < 30 else "MEDIUM" if score < 70 else "HIGH"
        color = "green" if score < 30 else "orange" if score < 70 else "red"
        
        summary = f"""URL Analysis Results for: {url}
        
Phishing Risk Score: {score}/100
Risk Level: {risk_level}

Summary:
"""
        self.summary_text.insert(tk.END, summary)
        self.summary_text.tag_add("risk", "3.0", "3.100")
        self.summary_text.tag_config("risk", foreground=color, font=('Arial', 12, 'bold'))
        
        # Add detailed findings
        for section in ['url_analysis', 'content_analysis', 'technical_analysis', 'reputation_analysis']:
            if section in results:
                section_data = results[section]
                if section_data.get('indicators'):
                    self.summary_text.insert(tk.END, f"\n{section.replace('_', ' ').title()}:\n")
                    for indicator in section_data['indicators']:
                        self.summary_text.insert(tk.END, f"• {indicator}\n")
                        
                        # Add to treeview
                        severity = "HIGH" if section_data['score'] > 10 else "MEDIUM" if section_data['score'] > 5 else "LOW"
                        self.results_tree.insert('', tk.END, values=(
                            section,
                            severity,
                            indicator,
                            f"Score: {section_data['score']}"
                        ))
        
        self.status_var.set("Analysis complete")
        self.notebook.select(2)  # Switch to results tab
    
    def display_file_results(self, results, directory):
        """Display file scan results"""
        self.current_results = results
        
        # Clear previous results
        self.summary_text.delete(1.0, tk.END)
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Display summary
        summary = f"""File Scan Results for: {directory}
        
Files Scanned: {results.get('total_files_scanned', 0)}
Suspicious Files Found: {results.get('malicious_files_found', 0)}

"""
        self.summary_text.insert(tk.END, summary)
        
        # Add file findings
        if results.get('suspicious_files'):
            self.summary_text.insert(tk.END, "Suspicious Files:\n")
            for file_info in results['suspicious_files']:
                self.summary_text.insert(tk.END, f"• {file_info['file']} - {file_info['reason']} ({file_info['severity']})\n")
                
                # Add to treeview
                self.results_tree.insert('', tk.END, values=(
                    "File Scan",
                    file_info['severity'].upper(),
                    file_info['file'],
                    file_info['reason']
                ))
        else:
            self.summary_text.insert(tk.END, "No suspicious files found.\n")
        
        self.status_var.set("Scan complete")
        self.notebook.select(2)  # Switch to results tab
    
    def browse_directory(self):
        """Browse for directory"""
        directory = filedialog.askdirectory()
        if directory:
            self.dir_entry.delete(0, tk.END)
            self.dir_entry.insert(0, directory)
    
    def export_report(self):
        """Export analysis report"""
        if not self.current_results:
            messagebox.showwarning("Warning", "No results to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    if filename.endswith('.json'):
                        json.dump(self.current_results, f, indent=2)
                    else:
                        f.write(self.summary_text.get(1.0, tk.END))
                
                messagebox.showinfo("Success", f"Report exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export report: {str(e)}")
    
    def clear_results(self):
        """Clear results"""
        self.summary_text.delete(1.0, tk.END)
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.current_results = None


# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = PhishingKitDetectorGUI(root)
    root.mainloop()
