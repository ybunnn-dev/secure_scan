import tkinter as tk
from tkinter import ttk
from tkinter import messagebox

class SuspiciousFileScannerUI:
    NAV_BG = "#5c6d91"
    NAV_ACTIVE_BG = "#465470"
    NAV_TEXT = "#ffffff"
    CONTENT_BG = "#f0f0f0"
    HEADER_BG = "#e0e0e0"
    FONT_NORMAL = ("Calibri", 12)
    FONT_BOLD = ("Calibri", 12, "bold")
    FONT_TITLE = ("Calibri", 16, "bold")

    def __init__(self, master):
        self.master = master
        master.title("ScanSecure")
        master.geometry("1100x700")
        master.configure(bg=self.CONTENT_BG)

        self.scanned_reports = {
            "2025-10-13_1930": {
                "total_scans": 15000, "vulnerable": 5, "files": [
                    {"path": "/home/user/malware.exe", "extension": ".exe", "size_bytes": 10240, "executable": True, "reasons": "suspicious_ext:.exe;executable"},
                    {"path": "/home/user/data.sh", "extension": ".sh", "size_bytes": 512, "executable": True, "reasons": "executable"},
                ]
            },
            "2025-10-13_2000": {
                "total_scans": 22000, "vulnerable": 8, "files": [
                    {"path": "/home/user/secret.zip", "extension": ".zip", "size_bytes": 55000000, "executable": False, "reasons": "large_file>50MB"},
                    {"path": "/home/user/temp/config", "extension": "<noext>", "size_bytes": 2048, "executable": False, "reasons": "no_extension"},
                    {"path": "/home/user/Documents/report.pdf", "extension": ".pdf", "size_bytes": 1500000, "executable": False, "reasons": ""},
                ]
            }
        }
        self.current_report_key = "2025-10-13_2000"
        self.all_data_in_table = {}

    
        self.setup_styles()

        self.create_main_layout()

        self.update_summary_report()
        self.load_report_data_to_table(self.current_report_key)
        self.update_report_switch_cbox()
        
        self.show_page("scanner")

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')

        style.configure('Nav.TButton', background=self.NAV_BG, foreground=self.NAV_TEXT, font=("Calibri", 14, "bold"), borderwidth=0, focusthickness=0)
        style.map('Nav.TButton', background=[('active', self.NAV_ACTIVE_BG)])
        
        style.configure('Scan.TButton', background="#8ea0c7", foreground=self.NAV_TEXT, font=("Calibri", 14, "bold"), padding=(20, 10))
        style.map('Scan.TButton', background=[('active', '#5c6d91')])

        style.configure("Treeview.Heading", font=self.FONT_BOLD, background="#5c6d91", foreground="white", padding=5)
        style.configure("Treeview", rowheight=25, font=self.FONT_NORMAL, fieldbackground="#ffffff")
        style.map("Treeview.Heading", background=[('active', '#465470')])

    def create_main_layout(self):
        sidebar = tk.Frame(self.master, bg=self.NAV_BG, width=200)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        tk.Label(sidebar, text="SCANSECURE", font=("Calibri", 20, "bold"), bg=self.NAV_BG, fg=self.NAV_TEXT).pack(pady=20)

        self.scanner_button = ttk.Button(sidebar, text="Basic Scanner", style='Nav.TButton', command=lambda: self.show_page("scanner"))
        self.scanner_button.pack(fill="x", pady=5, padx=10)

        self.files_button = ttk.Button(sidebar, text="Files Scanned", style='Nav.TButton', command=lambda: self.show_page("files"))
        self.files_button.pack(fill="x", pady=5, padx=10)
        
        self.content_area = tk.Frame(self.master, bg=self.CONTENT_BG)
        self.content_area.pack(side="right", fill="both", expand=True)

        self.page_scanner = self.setup_basic_scan_page()
        self.page_files = self.setup_files_table_page()
        
    def show_page(self, page_name):
        self.page_scanner.pack_forget()
        self.page_files.pack_forget()

        if page_name == "scanner":
            self.page_scanner.pack(fill="both", expand=True, padx=20, pady=20)
        elif page_name == "files":
            self.page_files.pack(fill="both", expand=True, padx=20, pady=20)

    def setup_basic_scan_page(self):
        page = tk.Frame(self.content_area, bg=self.CONTENT_BG)

        left_panel = tk.Frame(page, bg="white", highlightbackground="lightgrey", highlightthickness=1)
        left_panel.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        self.summary_canvas = tk.Canvas(left_panel, bg="white", highlightthickness=0)
        self.summary_canvas.pack(fill="both", expand=True, padx=20, pady=20)
        self.summary_canvas.bind("<Configure>", self.redraw_summary_circle)
        
        controls_frame = tk.Frame(left_panel, bg="white")
        controls_frame.pack(fill="x", pady=(0, 20))
        
        self.progress_bar = ttk.Progressbar(controls_frame, orient="horizontal", length=300, mode="determinate")
        self.progress_bar.pack(pady=5, padx=50, fill='x')
        
        self.progress_label_var = tk.StringVar(value="Progress: 0%")
        tk.Label(controls_frame, textvariable=self.progress_label_var, font=self.FONT_NORMAL, bg="white").pack()
        
        self.scan_status_var = tk.StringVar(value="Status: Ready")
        tk.Label(controls_frame, textvariable=self.scan_status_var, font=self.FONT_BOLD, bg="white").pack(pady=(0, 10))

        self.scan_button = ttk.Button(controls_frame, text="Scan Now", style='Scan.TButton', command=self.start_scan_simulated)
        self.scan_button.pack()
        
        right_panel = tk.Frame(page, bg="white", width=250, highlightbackground="lightgrey", highlightthickness=1)
        right_panel.pack(side="right", fill="y", padx=(10, 0))
        right_panel.pack_propagate(False)

        tk.Label(right_panel, text="Previous Scans", font=self.FONT_TITLE, bg="white").pack(pady=15)
        
        scan_history_frame = tk.Frame(right_panel, bg="white")
        scan_history_frame.pack(fill="x", padx=15)

        sorted_keys = sorted(self.scanned_reports.keys(), reverse=True)
        for report_key in sorted_keys:
            scan_item_frame = tk.Frame(scan_history_frame, bg=self.HEADER_BG, cursor="hand2")
            scan_item_frame.pack(fill="x", pady=4, ipady=10)
            
            display_text = report_key.replace('_', ' ')
            label = tk.Label(scan_item_frame, text=display_text, bg=self.HEADER_BG, font=self.FONT_NORMAL)
            label.pack()
            
            handler = lambda key=report_key: self.load_scan_from_history(key)
            scan_item_frame.bind("<Button-1>", handler)
            label.bind("<Button-1>", handler)
            
        return page

    def load_scan_from_history(self, report_key):
        self.load_report_data_to_table(report_key)
        self.update_report_switch_cbox()
        self.show_page("files")

    def redraw_summary_circle(self, event=None):
        canvas = self.summary_canvas
        canvas.delete("all")
        
        width = canvas.winfo_width()
        height = canvas.winfo_height()
        radius = min(width, height) * 0.35
        cx, cy = width / 2, height / 2

        canvas.create_oval(cx - radius, cy - radius, cx + radius, cy + radius, fill="#e0e5f5", width=15, outline="#8ea0c7")
        canvas.create_line(cx - radius*0.5, cy, cx + radius*0.5, cy, fill="#cccccc", width=1)
        
        self.scanned_text_id = canvas.create_text(cx, cy - radius*0.4, text="0", font=("Calibri", 30, "bold"), fill="#3e4a63")
        canvas.create_text(cx, cy - radius*0.1, text="Scanned Files", font=("Calibri", 12), fill="grey")
        
        self.vulnerable_text_id = canvas.create_text(cx, cy + radius*0.3, text="0", font=("Calibri", 30, "bold"), fill="red")
        canvas.create_text(cx, cy + radius*0.6, text="Suspicious Files", font=("Calibri", 12), fill="grey")
        
        self.update_summary_report()

    def setup_files_table_page(self):
        page = tk.Frame(self.content_area, bg=self.CONTENT_BG)

        control_frame = tk.Frame(page, bg=self.CONTENT_BG)
        control_frame.pack(fill='x', pady=(0, 10))

        ttk.Label(control_frame, text="Switch Report:", font=self.FONT_NORMAL, background=self.CONTENT_BG).pack(side='left', padx=(0, 5))
        self.report_switch_cbox = ttk.Combobox(control_frame, state="readonly", font=self.FONT_NORMAL)
        self.report_switch_cbox.pack(side='left', padx=(0, 20))
        self.report_switch_cbox.bind('<<ComboboxSelected>>', self.switch_report)

        ttk.Label(control_frame, text="Filter Results:", font=self.FONT_NORMAL, background=self.CONTENT_BG).pack(side='left', padx=(20, 5))
        self.filter_entry = ttk.Entry(control_frame, font=self.FONT_NORMAL)
        self.filter_entry.pack(side='left', fill='x', expand=True)
        self.filter_entry.bind('<KeyRelease>', self.filter_results_placeholder)

        results_frame = tk.Frame(page)
        results_frame.pack(fill='both', expand=True)
        
        columns = ("path", "extension", "size_bytes", "executable", "reasons")
        self.tree = ttk.Treeview(results_frame, columns=columns, show='headings')

        self.tree.heading("path", text="File Directory")
        self.tree.column("path", width=400)
        self.tree.heading("extension", text="Ext")
        self.tree.column("extension", width=70, anchor="center")
        self.tree.heading("size_bytes", text="Size (bytes)")
        self.tree.column("size_bytes", width=120, anchor="e")
        self.tree.heading("executable", text="Exec")
        self.tree.column("executable", width=60, anchor="center")
        self.tree.heading("reasons", text="Suspicious Reason")
        self.tree.column("reasons", width=300)

        vsb = ttk.Scrollbar(results_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self.tree.pack(fill='both', expand=True)
        self.tree.bind('<<TreeviewSelect>>', self.on_item_select)

        return page

    def update_summary_report(self):
        if not hasattr(self, 'scanned_text_id'): return 
        latest_key = sorted(self.scanned_reports.keys())[-1]
        report = self.scanned_reports[latest_key]
        self.summary_canvas.itemconfig(self.scanned_text_id, text=f"{report['total_scans']:,}")
        self.summary_canvas.itemconfig(self.vulnerable_text_id, text=f"{report['vulnerable']:,}")

    def update_report_switch_cbox(self):
        report_keys = sorted(self.scanned_reports.keys(), reverse=True)
        self.report_switch_cbox['values'] = report_keys
        if report_keys:
            self.report_switch_cbox.set(self.current_report_key)

    def load_report_data_to_table(self, report_key):
        self.current_report_key = report_key
        self.tree.delete(*self.tree.get_children())
        self.all_data_in_table.clear()
        
        if report_key not in self.scanned_reports: return
            
        files_list = self.scanned_reports[report_key]['files']
        for i, file_info in enumerate(files_list):
            item_id = f"I{i}"
            self.all_data_in_table[item_id] = file_info
            
            self.tree.insert("", "end", iid=item_id, values=(
                file_info['path'],
                file_info['extension'],
                f"{file_info['size_bytes']:,}",
                "Yes" if file_info['executable'] else "No",
                file_info['reasons'].split(';')[0]
            ))

    def start_scan_simulated(self):
        self.scan_button.config(state=tk.DISABLED)
        self.scan_status_var.set("Status: SCANNING...")
        
        for i in range(101):
            self.master.after(20 * i, lambda i=i: self.update_progress(i))

    def update_progress(self, percent):
        self.progress_bar['value'] = percent
        self.progress_label_var.set(f"Progress: {percent}%")
        if percent == 100:
            self.scan_status_var.set("Status: Scan Complete!")
            self.scan_button.config(state=tk.NORMAL)
            self.update_summary_report()

    def switch_report(self, event):
        selected_key = self.report_switch_cbox.get()
        if selected_key:
            self.load_report_data_to_table(selected_key)
            self.tree.selection_remove(self.tree.selection())

    def filter_results_placeholder(self, event=None):
        search_term = self.filter_entry.get().lower()
        print(f"Filtering logic for '{search_term}' would be implemented here.")

    def on_item_select(self, event):
        selected_items = self.tree.selection()
        if selected_items:
            item_id = selected_items[0]
            file_details = self.all_data_in_table.get(item_id)
            if file_details:
                self.create_details_popup(item_id, file_details)
                self.tree.selection_remove(item_id)
    
    def create_details_popup(self, item_id, file_details):
        popup = tk.Toplevel(self.master)
        popup.title("File Details")
        popup.geometry("500x300")
        popup.transient(self.master)
        popup.grab_set()

        details_frame = tk.Frame(popup, padx=20, pady=20)
        details_frame.pack(fill="both", expand=True)
        
      
        details = {
            "Full Path:": file_details['path'],
            "Extension:": file_details['extension'],
            "Size (bytes):": f"{file_details['size_bytes']:,}",
            "Executable:": "Yes" if file_details['executable'] else "No", 
            "Reasons:": file_details['reasons'].replace(';', '\n')
        }

        for i, (label, value) in enumerate(details.items()):
            tk.Label(details_frame, text=label, font=self.FONT_BOLD, anchor="nw").grid(row=i, column=0, sticky="nw", pady=2)
            # A typo was also corrected here: 'details_fame' to 'details_frame'
            tk.Label(details_frame, text=value, font=self.FONT_NORMAL, wraplength=350, justify="left").grid(row=i, column=1, sticky="nw", pady=2, padx=5)
        details_frame.grid_columnconfigure(1, weight=1)

        button_frame = tk.Frame(popup, bg=self.HEADER_BG)
        button_frame.pack(fill="x", side="bottom")
        
        ttk.Button(button_frame, text="Close", command=popup.destroy).pack(side="right", padx=10, pady=10)
        ttk.Button(button_frame, text="Delete Selected File", 
                   command=lambda: self.delete_file_from_popup(item_id, file_details['path'], popup)).pack(side="right", padx=10, pady=10)

    def delete_file_from_popup(self, item_id, file_path, popup):
        if messagebox.askyesno("Confirm Delete", f"Are you sure you want to DELETE '{file_path}'? This action cannot be undone.", parent=popup):
            popup.destroy()
            self.tree.delete(item_id)
            if item_id in self.all_data_in_table:
                del self.all_data_in_table[item_id]
            messagebox.showinfo("Success", f"File '{file_path}' has been SIMULATEDLY deleted.")

if __name__ == "__main__":
    root = tk.Tk()
    app = SuspiciousFileScannerUI(root)
    root.mainloop()