# SecureScan

SecureScan is a Linux-based security auditing tool designed to scan all files inside a user's home directory and identify potentially suspicious or unsafe files. It performs multiple security checks and generates flagging messages to help users detect possible malware, misconfigurations, or disguised executables.

---

##  Overview

SecureScan recursively scans every file in the user's home directory. For each file, it applies four layers of security checks focusing on permissions, file type, extension, and mismatches. After scanning all files, it returns a summarized report of flagged files and their respective issues.

---

## How SecureScan Works

### **1. Main Loop (File Scanning Process)**

SecureScan begins by scanning every file inside the user's home directory.

* The program checks whether all files have been scanned.
* If **not**, it proceeds to analyze the next file.
* Once **all files are scanned**, the system returns the complete set of analysis results.

### **2. Security Checks (Flagging Logic)**

SecureScan performs **four checks** on every file. If a file fails any test, a flagging message is added to the file's report.

* **Check 1: Execution Permissions**
    * *Question:* Does the file have the executable bit set?
    * *Why it matters:* Files in a home directory typically shouldn't be executable unless they are legitimate scripts or programs.
* **Check 2: File Signature Validation**
    * *Question:* Is the file signature suspicious?
    * *How it works:* Reads the file's *magic number* (binary header) and compares it against known malicious patterns.
* **Check 3: Suspicious Extension Check**
    * *Question:* Is the file extension known to be risky (e.g., `.exe`, `.bat`, `.sh`)?
* **Check 4: Signature vs. Extension Mismatch**
    * *Question:* Does the file's internal signature match its claimed extension?
    * *Example:* A file named `photo.jpg` that is actually an executable (`.exe`).

---

##  Installation & Usage

You can run SecureScan by running the source code directly.


### **Run from Source**
If you want to modify the code or contribute, you can clone the repository.

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/ybunnn-dev/secure_scan.git
    cd SecureScan
    ```

2.  **Install Dependencies:**
    You need Python 3 and the `python-magic` library.
    ```bash
    # Install system library (Debian/Ubuntu)
    sudo apt install libmagic1

    # Install Python requirements
    pip install tkinter
    pip install pandas
    pip install python-magic
    ```

3.  **Run the App:**
    ```bash
    python main.py
    ```

---

## Output

At the end of the scan, SecureScan produces a structured report containing:
* List of scanned files
* Any flagged files with specific warnings
* A compressed archive (`.tar.gz`) of the results saved in the `reports/` folder.

---

##  Goal

SecureScan aims to provide users with a simple but effective first line of defense by identifying unusual or potentially harmful files within their home directory, increasing security awareness and reducing unnoticed threats.

---

## Disclaimer

SecureScan is a detection tool, **not** a full antivirus solution. While it helps identify suspicious files, users should still use proper security practices and trusted antivirus software for complete protection.