import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import os
import sys
from datetime import datetime

class CyberSentinelGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberSentinel - Security Scanner")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # Configure style
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.configure_styles()
        
        self.create_widgets()
        self.scan_in_progress = False
        
    def configure_styles(self):
        """Configure custom styles for the application"""
        self.style.configure('TFrame', background='#f0f0f0')
        self.style.configure('TLabel', background='#f0f0f0', font=('Segoe UI', 10))
        self.style.configure('Header.TLabel', font=('Segoe UI', 16, 'bold'), foreground='#2c3e50')
        self.style.configure('TButton', font=('Segoe UI', 10))
        self.style.configure('Run.TButton', font=('Segoe UI', 10, 'bold'), foreground='white', background='#27ae60')
        self.style.configure('Stop.TButton', font=('Segoe UI', 10, 'bold'), foreground='white', background='#e74c3c')
        self.style.configure('TEntry', font=('Segoe UI', 10), padding=5)
        self.style.configure('TNotebook', background='#f0f0f0')
        self.style.configure('TNotebook.Tab', font=('Segoe UI', 10, 'bold'))
        
    def create_widgets(self):
        """Create and arrange all GUI widgets"""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        header_frame = ttk.Frame(main_frame)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        ttk.Label(header_frame, text="🛡️ CyberSentinel", style='Header.TLabel').pack(side=tk.LEFT)
        
        # Target input
        input_frame = ttk.LabelFrame(main_frame, text="Scan Target", padding=10)
        input_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(input_frame, text="Target URL/IP:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.target_entry = ttk.Entry(input_frame, width=50)
        self.target_entry.grid(row=0, column=1, padx=5, pady=5, sticky=tk.EW)
        self.target_entry.insert(0, "example.com")
        
        # Scan options
        options_frame = ttk.LabelFrame(main_frame, text="Scan Options", padding=10)
        options_frame.pack(fill=tk.X, pady=5)
        
        # Port range
        ttk.Label(options_frame, text="Port Range:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.port_range = ttk.Combobox(options_frame, values=["Top 1000", "1-1024", "1-65535", "Custom"], width=15)
        self.port_range.grid(row=0, column=1, padx=5, pady=5, sticky=tk.W)
        self.port_range.set("Top 1000")
        
        # Scan type
        ttk.Label(options_frame, text="Scan Type:").grid(row=0, column=2, sticky=tk.W, padx=20, pady=5)
        self.scan_type = ttk.Combobox(options_frame, values=["Quick Scan", "Full Scan", "Vulnerability Scan"], width=20)
        self.scan_type.grid(row=0, column=3, padx=5, pady=5, sticky=tk.W)
        self.scan_type.set("Quick Scan")
        
        # Button frame
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        self.run_button = ttk.Button(button_frame, text="▶ Start Scan", command=self.start_scan, style='Run.TButton')
        self.run_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="⏹ Stop", command=self.stop_scan, style='Stop.TButton', state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)
        
        self.save_button = ttk.Button(button_frame, text="💾 Save Report", command=self.save_report, state=tk.DISABLED)
        self.save_button.pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, orient=tk.HORIZONTAL, length=100, mode='determinate')
        self.progress.pack(fill=tk.X, pady=10)
        
        # Output area
        output_frame = ttk.LabelFrame(main_frame, text="Scan Results", padding=10)
        output_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Create a notebook for different output tabs
        self.notebook = ttk.Notebook(output_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Console output tab
        console_tab = ttk.Frame(self.notebook)
        self.notebook.add(console_tab, text="Console")
        
        self.console = scrolledtext.ScrolledText(console_tab, wrap=tk.WORD, font=('Consolas', 10), bg='#1e1e1e', fg='#ffffff')
        self.console.pack(fill=tk.BOTH, expand=True)
        
        # Vulnerabilities tab
        vuln_tab = ttk.Frame(self.notebook)
        self.notebook.add(vuln_tab, text="Vulnerabilities")
        
        columns = ('Severity', 'Vulnerability', 'Port', 'Description')
        self.vuln_tree = ttk.Treeview(vuln_tab, columns=columns, show='headings')
        
        # Configure columns
        for col in columns:
            self.vuln_tree.heading(col, text=col)
            self.vuln_tree.column(col, width=100, anchor=tk.W)
        
        self.vuln_tree.column('Description', width=300)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(vuln_tab, orient=tk.VERTICAL, command=self.vuln_tree.yview)
        self.vuln_tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.vuln_tree.pack(fill=tk.BOTH, expand=True)
        
        # Status bar
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(fill=tk.X, pady=(5, 0))
        
        # Redirect stdout to console
        self.original_stdout = sys.stdout
        sys.stdout = self.ConsoleRedirector(self.console, self.original_stdout)
        
        print("CyberSentinel GUI initialized. Enter a target and click 'Start Scan'.")
    
    class ConsoleRedirector:
        """Helper class to redirect stdout to the console widget"""
        def __init__(self, text_widget, original_stdout):
            self.text_widget = text_widget
            self.original_stdout = original_stdout
            
        def write(self, text):
            self.text_widget.insert(tk.END, text)
            self.text_widget.see(tk.END)
            self.original_stdout.write(text)
            
        def flush(self):
            self.original_stdout.flush()
    
    def start_scan(self):
        """Start the scan in a separate thread"""
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showerror("Error", "Please enter a target URL or IP address")
            return
            
        self.scan_in_progress = True
        self.run_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.save_button.config(state=tk.DISABLED)
        self.progress['value'] = 0
        self.status_var.set("Scanning: " + target)
        
        # Clear previous results
        self.console.delete(1.0, tk.END)
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
        
        # Start scan in a separate thread
        scan_thread = threading.Thread(target=self.run_scan, args=(target,), daemon=True)
        scan_thread.start()
        
        # Start progress bar animation
        self.animate_progress()
    
    def run_scan(self, target):
        """Run the actual scan (to be implemented with CyberSentinel functionality)"""
        try:
            print(f"Starting scan of {target}...\n")
            
            # Simulate scan progress (replace with actual CyberSentinel scan)
            for i in range(1, 11):
                if not self.scan_in_progress:
                    break
                    
                # Simulate different scan phases
                if i == 3:
                    print("✓ Port scanning completed")
                    self.add_vulnerability("Info", "Open ports found", "80, 443, 22", "Common web and SSH ports are open")
                elif i == 5:
                    print("✓ Service detection completed")
                    self.add_vulnerability("Medium", "Outdated Apache version", "80", "Apache 2.4.29 is outdated and has known vulnerabilities")
                elif i == 7:
                    print("✓ Vulnerability assessment in progress...")
                    self.add_vulnerability("High", "SQL Injection vulnerability", "80", "SQL injection possible in login form")
                elif i == 9:
                    print("✓ SSL/TLS analysis completed")
                    self.add_vulnerability("Critical", "Weak SSL Cipher", "443", "TLS_RSA_WITH_3DES_EDE_CBC_SHA is considered weak")
                
                # Update progress
                self.root.after(100, lambda: self.progress.step(10))
                time.sleep(1)  # Simulate work
                
            if self.scan_in_progress:
                print("\n✓ Scan completed successfully!")
                self.status_var.set("Scan completed - " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                self.save_button.config(state=tk.NORMAL)
            else:
                print("\n✗ Scan was stopped by user")
                self.status_var.set("Scan stopped - " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                
        except Exception as e:
            print(f"\n✗ Error during scan: {str(e)}")
            self.status_var.set(f"Error: {str(e)}")
            
        finally:
            self.scan_in_progress = False
            self.root.after(100, self.scan_completed)
    
    def stop_scan(self):
        """Stop the currently running scan"""
        if messagebox.askyesno("Confirm", "Are you sure you want to stop the scan?"):
            self.scan_in_progress = False
            self.status_var.set("Stopping scan...")
    
    def scan_completed(self):
        """Clean up after scan completes or is stopped"""
        self.run_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.progress['value'] = 100
        
    def add_vulnerability(self, severity, vuln_name, port, description):
        """Add a vulnerability to the vulnerabilities tab"""
        # Map severity to color tags
        severity_colors = {
            'Critical': '#ff0000',
            'High': '#ff6b6b',
            'Medium': '#ffd93d',
            'Low': '#4d96ff',
            'Info': '#6bcb77'
        }
        
        tag = f"severity_{severity}"
        self.vuln_tree.insert('', 'end', values=(severity, vuln_name, port, description), tags=(tag,))
        self.vuln_tree.tag_configure(tag, background=severity_colors.get(severity, '#ffffff'))
    
    def save_report(self):
        """Save the scan report to a file"""
        file_types = [
            ('PDF Report', '*.pdf'),
            ('HTML Report', '*.html'),
            ('Text Report', '*.txt'),
            ('All Files', '*.*')
        ]
        
        default_file = f"cybersentinel_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        file_path = filedialog.asksaveasfilename(
            defaultextension='.pdf',
            filetypes=file_types,
            initialfile=default_file,
            title="Save Scan Report As"
        )
        
        if file_path:
            try:
                # In a real implementation, this would generate the actual report
                with open(file_path, 'w') as f:
                    f.write("CyberSentinel Security Scan Report\n")
                    f.write("=" * 40 + "\n\n")
                    f.write(f"Target: {self.target_entry.get()}\n")
                    f.write(f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                    f.write("Vulnerabilities Found:\n")
                    f.write("-" * 40 + "\n")
                    
                    # Add vulnerability details
                    for item in self.vuln_tree.get_children():
                        values = self.vuln_tree.item(item, 'values')
                        f.write(f"Severity: {values[0]}\n")
                        f.write(f"Vulnerability: {values[1]}\n")
                        f.write(f"Port: {values[2]}\n")
                        f.write(f"Description: {values[3]}\n\n")
                
                messagebox.showinfo("Success", f"Report saved successfully to:\n{file_path}")
                
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save report:\n{str(e)}")
    
    def animate_progress(self):
        """Animate the progress bar during scan"""
        if self.scan_in_progress:
            current = self.progress['value']
            if current < 90:  # Don't go to 100% until scan is complete
                self.progress['value'] = current + 1
            self.root.after(100, self.animate_progress)

def main():
    root = tk.Tk()
    app = CyberSentinelGUI(root)
    
    # Set window icon if available
    try:
        root.iconbitmap('icon.ico')  # Make sure to have an icon.ico file in the same directory
    except:
        pass  # Use default icon if custom icon not available
    
    # Handle window close
    def on_closing():
        if app.scan_in_progress:
            if messagebox.askokcancel("Quit", "A scan is in progress. Are you sure you want to quit?"):
                app.scan_in_progress = False
                root.destroy()
        else:
            root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    
    # Start the application
    root.mainloop()

if __name__ == "__main__":
    main()
