# scanner_gui.py
import tkinter as tk
from tkinter import ttk, messagebox
import threading

# IMPORT THE SEPARATED MODULES
import scan_device
import review

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

        self.available_archives = [] 
        self.current_table_data = {}
    
        self.setup_styles()
        self.create_main_layout()
        
        # Use REVIEW module to get lists
        self.refresh_archive_list()
        self.show_page("scanner")

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('Nav.TButton', background=self.NAV_BG, foreground=self.NAV_TEXT, font=("Calibri", 14, "bold"), borderwidth=0)
        style.map('Nav.TButton', background=[('active', self.NAV_ACTIVE_BG)])
        style.configure('Scan.TButton', background="#8ea0c7", foreground=self.NAV_TEXT, font=("Calibri", 14, "bold"), padding=(20, 10))
        style.map('Scan.TButton', background=[('active', '#5c6d91')])
        style.configure("Treeview.Heading", font=self.FONT_BOLD, background="#5c6d91", foreground="white")
        style.configure("Treeview", rowheight=25, font=self.FONT_NORMAL)

    def create_main_layout(self):
        sidebar = tk.Frame(self.master, bg=self.NAV_BG, width=200)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)

        tk.Label(sidebar, text="SCANSECURE", font=("Calibri", 20, "bold"), bg=self.NAV_BG, fg=self.NAV_TEXT).pack(pady=20)
        ttk.Button(sidebar, text="Scanner", style='Nav.TButton', command=lambda: self.show_page("scanner")).pack(fill="x", pady=5, padx=10)
        ttk.Button(sidebar, text="View Logs", style='Nav.TButton', command=lambda: self.show_page("files")).pack(fill="x", pady=5, padx=10)
        
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
            self.refresh_archive_list()
            self.page_files.pack(fill="both", expand=True, padx=20, pady=20)

    # --- SCANNER UI ---
    def setup_basic_scan_page(self):
        page = tk.Frame(self.content_area, bg=self.CONTENT_BG)
        center = tk.Frame(page, bg="white", highlightthickness=1)
        center.pack(side="top", fill="both", expand=True, padx=50, pady=50)

        tk.Label(center, text="System Security Scanner", font=self.FONT_TITLE, bg="white").pack(pady=(40, 20))
        
        self.progress_bar = ttk.Progressbar(center, orient="horizontal", mode="indeterminate", length=400)
        self.progress_bar.pack(pady=10)
        
        self.progress_label_var = tk.StringVar(value="Ready to Scan")
        tk.Label(center, textvariable=self.progress_label_var, font=self.FONT_NORMAL, bg="white").pack()
        
        self.scan_button = ttk.Button(center, text="Start Deep Scan", style='Scan.TButton', command=self.start_scan_thread)
        self.scan_button.pack(pady=30)
        return page

    # --- FILES UI ---
    def setup_files_table_page(self):
        page = tk.Frame(self.content_area, bg=self.CONTENT_BG)
        
        top = tk.Frame(page, bg=self.CONTENT_BG); top.pack(fill='x', pady=(0, 10))
        ttk.Label(top, text="Select Past Scan Report:", font=self.FONT_NORMAL).pack(side='left')
        
        self.report_cbox = ttk.Combobox(top, state="readonly", font=self.FONT_NORMAL, width=40)
        self.report_cbox.pack(side='left', padx=10)
        self.report_cbox.bind('<<ComboboxSelected>>', self.on_archive_selected)
        
        ttk.Button(top, text="Refresh List", command=self.refresh_archive_list).pack(side='left')

        cols = ("path", "extension", "size", "exec", "reasons")
        self.tree = ttk.Treeview(page, columns=cols, show='headings')
        self.tree.heading("path", text="Path"); self.tree.column("path", width=350)
        self.tree.heading("extension", text="Ext"); self.tree.column("extension", width=60, anchor="center")
        self.tree.heading("size", text="Size"); self.tree.column("size", width=80, anchor="e")
        self.tree.heading("exec", text="Exec"); self.tree.column("exec", width=50, anchor="center")
        self.tree.heading("reasons", text="Flags"); self.tree.column("reasons", width=300)
        
        vsb = ttk.Scrollbar(page, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self.tree.pack(fill='both', expand=True)
        self.tree.bind('<<TreeviewSelect>>', self.on_item_select)
        return page

    # --- REVIEW LOGIC (Using review.py) ---
    def refresh_archive_list(self):
        # Call review.py
        self.available_archives = review.get_available_archives()
        
        display_values = [f"{item['display_time']}  [{os.path.basename(item['filename'])}]" for item in self.available_archives]
        self.report_cbox['values'] = display_values
        if display_values:
            self.report_cbox.current(0)

    def on_archive_selected(self, event):
        idx = self.report_cbox.current()
        if idx == -1: return
        
        selected_archive = self.available_archives[idx]['filename']
        
        # Call review.py
        data = review.load_archive_to_results(selected_archive)
        self.populate_table(data)

    def populate_table(self, data):
        self.tree.delete(*self.tree.get_children())
        self.current_table_data.clear()
        
        for i, row in enumerate(data):
            iid = f"item_{i}"
            self.current_table_data[iid] = row
            self.tree.insert("", "end", iid=iid, values=(
                row['path'], row['extension'], f"{row['size_bytes']:,}", 
                "Yes" if row['executable'] else "No", row['reasons']
            ))

    # --- SCAN LOGIC (Using scan_device.py) ---
    def start_scan_thread(self):
        self.scan_button.config(state=tk.DISABLED)
        self.progress_bar.start(10)
        self.progress_label_var.set("Scanning Home Directory...")
        threading.Thread(target=self.run_scan_backend, daemon=True).start()

    def run_scan_backend(self):
        def update_ui(count, fpath):
            self.master.after(0, lambda: self.progress_label_var.set(f"Scanning ({count}): ...{fpath[-30:]}"))

        # Call scan_device.py
        count, vuln, files = scan_device.scan_home_directory(scan_device.HOME, update_ui)
        archive, msg = scan_device.save_report_archive(files)
        
        self.master.after(0, lambda: self.finish_scan(count, vuln, msg))

    def finish_scan(self, count, vuln, msg):
        self.progress_bar.stop()
        self.progress_label_var.set(f"Done. Found {vuln} suspicious files.")
        self.scan_button.config(state=tk.NORMAL)
        messagebox.showinfo("Scan Complete", f"{msg}\n\nSuspicious files: {vuln}")
        self.refresh_archive_list()

    # --- DELETE LOGIC (Using scan_device.py) ---
    def on_item_select(self, event):
        sel = self.tree.selection()
        if sel: self.show_popup(sel[0])

    def show_popup(self, iid):
        data = self.current_table_data[iid]
        pop = tk.Toplevel(self.master)
        pop.title("Details")
        pop.geometry("600x400")
        
        txt = f"Path: {data['path']}\nReasons: {data['reasons']}"
        tk.Label(pop, text=txt, wraplength=580, justify="left").pack(pady=20)
        
        def delete_fn():
            if messagebox.askyesno("Delete", "Delete this file?"):
                # Call scan_device.py for deletion
                ok, m = scan_device.delete_file(data['path'])
                if ok: 
                    self.tree.delete(iid)
                    pop.destroy()
                messagebox.showinfo("Result", m)
        
        tk.Button(pop, text="Delete File", bg="red", fg="white", command=delete_fn).pack()