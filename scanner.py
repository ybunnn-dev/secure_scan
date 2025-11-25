#!/usr/bin/env python3
import os
import collections
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime

HOME = os.path.expanduser("~")
EXCLUDE_DIRS = {"/proc", "/sys", "/dev", "/run", "/var/lib", "/var/run", "/tmp", "/mnt", "/media"}
MALICIOUS_EXTENSIONS = {'.exe', '.dll', '.bat', '.cmd', '.com', '.scr', '.vbs', '.js', '.ps1', '.jar', '.apk', '.elf'}
LARGE_FILE_THRESHOLD = 50 * 1024 * 1024  # 50 MB

def is_excluded(path):
    return any(os.path.commonpath([path, e]) == e for e in EXCLUDE_DIRS)

def scan_home_suspicious(root):
    files_info = []
    counts = collections.Counter()
    for dirpath, dirnames, filenames in os.walk(root, topdown=True, followlinks=False):
        if is_excluded(dirpath):
            dirnames[:] = []
            continue
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            if not os.path.isfile(fpath):
                continue
            size = os.path.getsize(fpath)
            ext = os.path.splitext(fname)[1].lower() or "<noext>"
            counts[ext] += 1
            is_exec = os.access(fpath, os.X_OK)
            # Flag suspicious files
            suspicious = False
            reasons = []
            if ext == "<noext>":
                suspicious = True
                reasons.append("no_extension")
            if ext in MALICIOUS_EXTENSIONS:
                suspicious = True
                reasons.append(f"suspicious_ext:{ext}")
            if is_exec:
                suspicious = True
                reasons.append("executable")
            if size >= LARGE_FILE_THRESHOLD:
                suspicious = True
                reasons.append(f"large_file>{LARGE_FILE_THRESHOLD}B")
            files_info.append({
                "path": fpath,
		"file_name": fname,
                "extension": ext,
                "size_bytes": size,
                "executable": is_exec,
                "suspicious": suspicious,
                "reasons": ';'.join(reasons)
            })
    return counts, files_info

# === Run scan ===
counts, files_info = scan_home_suspicious(HOME)
df_files = pd.DataFrame(files_info)

# === Save detailed suspicious files report ===
df_suspicious = df_files[df_files["suspicious"]]
timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
report_file = f"suspicious_files_report_{timestamp}.csv"
df_suspicious.to_csv(report_file, index=False)
print(f"Suspicious files report saved to: {report_file}")

# === Prepare summary report ===
top_n = 20
most_common = counts.most_common(top_n)
df_summary = pd.DataFrame(most_common, columns=["extension", "count"])
df_summary["percent"] = (df_summary["count"] / df_files.shape[0] * 100).round(2)
total_files = df_files.shape[0]
total_suspicious = df_suspicious.shape[0]

summary_file = "suspicious_files_summary.csv"
summary_row = {
    "timestamp": timestamp,
    "total_files_scanned": total_files,
    "total_suspicious_files": total_suspicious,
    "top_extensions": ";".join([f"{ext}:{cnt}" for ext, cnt in most_common])
}

# Append to summary CSV
if os.path.exists(summary_file):
    df_summary_csv = pd.read_csv(summary_file)
    df_summary_csv = pd.concat([df_summary_csv, pd.DataFrame([summary_row])], ignore_index=True)
else:
    df_summary_csv = pd.DataFrame([summary_row])

df_summary_csv.to_csv(summary_file, index=False)
print(f"Summary report updated/appended to: {summary_file}")

# === Optional: Plot top extensions ===
plt.figure(figsize=(12,6))
plt.bar(df_summary["extension"], df_summary["count"])
plt.xticks(rotation=45, ha='right')
plt.title(f"Top {len(df_summary)} file types in {HOME}")
plt.xlabel("File extension")
plt.ylabel("File count")
plt.tight_layout()
plt.show()
