# main.py
import tkinter as tk
from scanner_gui import SuspiciousFileScannerUI

if __name__ == "__main__":
    root = tk.Tk()
    app = SuspiciousFileScannerUI(root)
    root.mainloop()