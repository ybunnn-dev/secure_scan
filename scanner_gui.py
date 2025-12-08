# scanner_gui.py
import tkinter as tk
from tkinter import ttk, messagebox
import threading
from datetime import datetime
import scanner_core  # Import our backend

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

        self.scanned_reports = {} 
        self.current_report_key = None
        self.all_data_in_table = {}
    
        self.setup_styles()
        self.create_main_layout()
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
        ttk.Button(sidebar, text="Scanner Dashboard", style='Nav.TButton', command=lambda: self.show_page("scanner")).pack(fill="x", pady=5, padx=10)
        ttk.Button(sidebar, text="View Files", style='Nav.TButton', command=lambda: self.show_page("files")).pack(fill="x", pady=5, padx=10)
        
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
        left = tk.Frame(page, bg="white", highlightthickness=1); left.pack(side="left", fill="both", expand=True, padx=(0, 10))
        
        self.summary_canvas = tk.Canvas(left, bg="white", highlightthickness=0)
        self.summary_canvas.pack(fill="both", expand=True, padx=20, pady=20)
        self.summary_canvas.bind("<Configure>", self.redraw_summary_circle)
        
        ctrl = tk.Frame(left, bg="white"); ctrl.pack(fill="x", pady=(0, 20))
        
        self.progress_bar = ttk.Progressbar(ctrl, orient="horizontal", mode="indeterminate")
        self.progress_bar.pack(pady=5, padx=50, fill='x')
        
        self.progress_label_var = tk.StringVar(value="Status: Idle")
        tk.Label(ctrl, textvariable=self.progress_label_var, font=self.FONT_NORMAL, bg="white").pack()
        
        self.scan_button = ttk.Button(ctrl, text="Start Deep Scan", style='Scan.TButton', command=self.start_scan_thread)
        self.scan_button.pack(pady=10)
        
        right = tk.Frame(page, bg="white", width=250, highlightthickness=1); right.pack(side="right", fill="y", padx=(10, 0))
        tk.Label(right, text="Scan History", font=self.FONT_TITLE, bg="white").pack(pady=15)
        self.history_frame = tk.Frame(right, bg="white"); self.history_frame.pack(fill="x", padx=15)
        
        return page

    def setup_files_table_page(self):
        page = tk.Frame(self.content_area, bg=self.CONTENT_BG)
        
        top = tk.Frame(page, bg=self.CONTENT_BG); top.pack(fill='x', pady=(0, 10))
        ttk.Label(top, text="Current Report:", font=self.FONT_NORMAL).pack(side='left')
        
        self.report_cbox = ttk.Combobox(top, state="readonly", font=self.FONT_NORMAL)
        self.report_cbox.pack(side='left', padx=10)
        self.report_cbox.bind('<<ComboboxSelected>>', self.switch_report)

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

    def start_scan_thread(self):
        self.scan_button.config(state=tk.DISABLED)
        self.progress_bar.start(10)
        self.progress_label_var.set("Initializing scan...")
        threading.Thread(target=self.run_scan_backend, daemon=True).start()

    def run_scan_backend(self):
        timestamp = datetime.now().strftime("%Y-%m-%d_%H:%M")
        
        def update_ui_progress(count, fpath):
            self.master.after(0, lambda: self.progress_label_var.set(f"Scanning ({count}): ...{fpath[-30:]}"))

        # 1. Run Scan
        scanned_count, vulnerable_count, files_info = scanner_core.scan_home_directory(scanner_core.HOME, update_ui_progress)
        
        # 2. Save Archive (CSV + TXT -> GZIP)
        archive_path, save_msg = scanner_core.save_report_archive(files_info)

        report_data = {
            "total_scans": scanned_count,
            "vulnerable": vulnerable_count,
            "files": files_info,
            "archive_path": archive_path  # Store path for UI reference
        }
        
        # 3. Update UI
        self.master.after(0, lambda: self.finish_scan(timestamp, report_data, save_msg))

    def finish_scan(self, key, data, save_msg):
        self.scanned_reports[key] = data
        self.progress_bar.stop()
        self.progress_label_var.set(f"Complete. Scanned {data['total_scans']} files.")
        self.scan_button.config(state=tk.NORMAL)
        
        self.update_history_sidebar()
        self.load_report_data(key)
        self.redraw_summary_circle()
        
        # Show success message with archive location
        messagebox.showinfo("Scan Complete", f"Found {data['vulnerable']} suspicious files.\n\n{save_msg}")

    def update_history_sidebar(self):
        for widget in self.history_frame.winfo_children(): widget.destroy()
        for key in sorted(self.scanned_reports.keys(), reverse=True):
            btn = tk.Label(self.history_frame, text=key, bg=self.HEADER_BG, pady=5, cursor="hand2")
            btn.pack(fill="x", pady=2)
            btn.bind("<Button-1>", lambda e, k=key: self.load_report_from_history(k))
        self.report_cbox['values'] = list(self.scanned_reports.keys())

    def load_report_from_history(self, key):
        self.load_report_data(key)
        self.show_page("files")

    def load_report_data(self, key):
        self.current_report_key = key
        self.report_cbox.set(key)
        self.tree.delete(*self.tree.get_children())
        self.all_data_in_table.clear()
        
        files = self.scanned_reports[key]['files']
        for i, f in enumerate(files):
            iid = f"item_{i}"
            self.all_data_in_table[iid] = f
            self.tree.insert("", "end", iid=iid, values=(
                f['path'], f['extension'], f"{f['size_bytes']:,}", 
                "Yes" if f['executable'] else "No", f['reasons']
            ))
        self.redraw_summary_circle()

    def switch_report(self, event):
        self.load_report_data(self.report_cbox.get())

    def redraw_summary_circle(self, event=None):
        self.summary_canvas.delete("all")
        if not self.current_report_key: return
        
        data = self.scanned_reports[self.current_report_key]
        w, h = self.summary_canvas.winfo_width(), self.summary_canvas.winfo_height()
        cx, cy = w/2, h/2
        
        self.summary_canvas.create_text(cx, cy-40, text=str(data['total_scans']), font=("Calibri", 30, "bold"), fill="#3e4a63")
        self.summary_canvas.create_text(cx, cy-10, text="Files Scanned", fill="grey")
        self.summary_canvas.create_text(cx, cy+40, text=str(data['vulnerable']), font=("Calibri", 30, "bold"), fill="red")
        self.summary_canvas.create_text(cx, cy+70, text="Suspicious", fill="grey")

    def on_item_select(self, event):
        sel = self.tree.selection()
        if sel:
            self.show_popup(sel[0])

    def show_popup(self, iid):
        data = self.all_data_in_table[iid]
        pop = tk.Toplevel(self.master)
        pop.title("File Details")
        pop.geometry("600x400")
        
        info = f"Path: {data['path']}\nSize: {data['size_bytes']} bytes\nReasons: {data['reasons']}"
        tk.Label(pop, text=info, justify="left", wraplength=580).pack(pady=20, padx=10)
        
        def delete_action():
            if messagebox.askyesno("Delete?", "Permanently delete this file?"):
                success, msg = scanner_core.delete_file(data['path'])
                if success:
                    self.tree.delete(iid)
                    messagebox.showinfo("Deleted", msg)
                    pop.destroy()
                else:
                    messagebox.showerror("Error", msg)

        tk.Button(pop, text="Delete File", bg="red", fg="white", command=delete_action).pack(pady=10)