#!/usr/bin/env python3
import os
import collections
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
import magic  # Essential for "File Signature" checks

HOME = os.path.expanduser("~")
EXCLUDE_DIRS = {"/proc", "/sys", "/dev", "/run", "/var/lib", "/var/run", "/tmp", "/mnt", "/media", "/snap"}

# Extensions that are inherently risky
SUSPICIOUS_EXTENSIONS = {'.exe', '.dll', '.bat', '.cmd', '.sh', '.vbs', '.js', '.ps1', '.elf'}

# Map mime-types to expected extensions for the "Mismatch" check
# This helps us answer: "Is file extension != file signature?"
MIME_TO_EXT = {
    'application/x-dosexec': ['.exe', '.dll', '.com'],
    'application/x-executable': ['.elf', '.bin'],
    'image/jpeg': ['.jpg', '.jpeg'],
    'image/png': ['.png'],
    'application/pdf': ['.pdf'],
    'text/plain': ['.txt', '.log', '.md', '.py', '.c', '.cpp'],
    'application/zip': ['.zip', '.docx', '.xlsx']
}

def is_excluded(path):
    return any(os.path.commonpath([path, e]) == e for e in EXCLUDE_DIRS)

def scan_home_flowchart_logic(root):
    files_info = []
    counts = collections.Counter()
    
    # Initialize Magic object for signature reading
    mime_detector = magic.Magic(mime=True)

    print(f"Starting scan on: {root}")

    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        # Skip excluded directories
        if is_excluded(dirpath):
            dirnames[:] = []
            continue
            
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            
            # Basic checks to ensure we can read the file
            if not os.path.isfile(fpath) or os.path.islink(fpath):
                continue
            
            try:
                # 1. Gather Basic Data
                size = os.path.getsize(fpath)
                ext = os.path.splitext(fname)[1].lower()
                counts[ext if ext else "<no_ext>"] += 1
                
                # Flowchart Logic Variables
                flag_messages = []
                
                # --- Flowchart Step 1: File permissions has execute bit? ---
                is_exec = os.access(fpath, os.X_OK)
                if is_exec:
                    # We usually only care if it's executable but NOT in a bin folder or is a weird extension
                    flag_messages.append("permissions_executable_bit_set")

                # --- Flowchart Step 2: File signature is suspicious? ---
                # We read the "magic number" (MIME type)
                try:
                    file_signature = mime_detector.from_file(fpath)
                except Exception:
                    file_signature = "unknown/error"

                # distinct "suspicious signatures" (e.g., finding an executable header)
                if 'dosexec' in file_signature or 'x-executable' in file_signature:
                     flag_messages.append(f"suspicious_signature:{file_signature}")

                # --- Flowchart Step 3: File extension is suspicious? ---
                if ext in SUSPICIOUS_EXTENSIONS:
                    flag_messages.append(f"suspicious_extension:{ext}")

                # --- Flowchart Step 4: Is file extension != file signature? ---
                # This detects "Masquerading" (e.g., malware.exe renamed to safe.jpg)
                is_mismatch = False
                if file_signature in MIME_TO_EXT:
                    # If the actual header is known, check if the extension matches one of the valid ones
                    if ext not in MIME_TO_EXT[file_signature]:
                        is_mismatch = True
                        flag_messages.append(f"mismatch_sig({file_signature})_vs_ext({ext})")

                # --- Flowchart Final Decision: Is flag message empty? ---
                suspicious = len(flag_messages) > 0
                
                # Filter: To reduce noise, you might ignore "executable bit" on known safe scripts 
                # if that is the ONLY flag, but strictly following your flowchart, we record it.

                if suspicious:
                    files_info.append({
                        "path": fpath,
                        "file_name": fname,
                        "extension": ext,
                        "signature": file_signature,
                        "size_bytes": size,
                        "reasons": "; ".join(flag_messages)
                    })

            except PermissionError:
                # Common when scanning root/system files
                continue
            except Exception as e:
                print(f"Error reading {fpath}: {e}")

    return counts, files_info

# === Run Scan ===
counts, files_info = scan_home_flowchart_logic(HOME)
df_files = pd.DataFrame(files_info)

# === Reporting Logic (Same as your original, just updated columns) ===
if not df_files.empty:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = f"suspicious_files_flowchart_{timestamp}.csv"
    
    # Save Report
    df_files.to_csv(report_file, index=False)
    print(f"\n[DONE] Suspicious files report saved to: {report_file}")
    print(f"Total Suspicious Files Found: {len(df_files)}")
    
    # Preview Top 5
    print("\nTop 5 Suspicious Files:")
    print(df_files[['file_name', 'reasons']].head(5).to_string())

    # === Plotting ===
    # Simple bar chart of the *Reasons* for flagging
    all_reasons = []
    for reasons in df_files['reasons']:
        all_reasons.extend(reasons.split('; '))
    
    reason_counts = collections.Counter(all_reasons)
    
    plt.figure(figsize=(10,6))
    plt.bar(reason_counts.keys(), reason_counts.values(), color='salmon')
    plt.xticks(rotation=45, ha='right')
    plt.title("Breakdown of Why Files Were Flagged")
    plt.tight_layout()
    plt.show()

else:
    print("Great news! No files matched the suspicious criteria.")