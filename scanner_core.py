# scanner_core.py
import os
import csv
import time
import tarfile
import magic  # pip install python-magic
from datetime import datetime

# Configuration
HOME = os.path.expanduser("~")
EXCLUDE_DIRS = {"/proc", "/sys", "/dev", "/run", "/var/lib", "/var/run", "/tmp", "/mnt", "/media", "/snap"}
SUSPICIOUS_EXTENSIONS = {'.exe', '.dll', '.bat', '.cmd', '.sh', '.vbs', '.js', '.ps1', '.elf', '.apk'}

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

def delete_file(path):
    try:
        if os.path.exists(path):
            os.remove(path)
            return True, "File deleted successfully."
        return False, "File not found."
    except Exception as e:
        return False, str(e)

def save_report_archive(files_info):
    """
    Saves results to CSV and TXT, then bundles them into a .tar.gz archive.
    """
    if not files_info:
        return None, "No files to save."

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"scan_report_{timestamp}"
    
    csv_filename = f"{base_name}.csv"
    txt_filename = f"{base_name}_meta.txt"
    archive_filename = f"{base_name}.tar.gz"

    try:
        # 1. Create CSV File
        with open(csv_filename, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=["path", "file_name", "extension", "size_bytes", "executable", "reasons"])
            writer.writeheader()
            for row in files_info:
                # Filter out extra keys if any
                clean_row = {k: row[k] for k in writer.fieldnames}
                writer.writerow(clean_row)

        # 2. Create Text File with Timestamp
        with open(txt_filename, mode='w', encoding='utf-8') as f:
            f.write(f"Scan Report Generated\n")
            f.write(f"=====================\n")
            f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Suspicious Files: {len(files_info)}\n")
            f.write(f"Scanned Directory: {HOME}\n")

        # 3. Compress into .tar.gz
        with tarfile.open(archive_filename, "w:gz") as tar:
            tar.add(csv_filename, arcname=csv_filename)
            tar.add(txt_filename, arcname=txt_filename)

        # 4. Cleanup temporary files (optional, keeps folder clean)
        os.remove(csv_filename)
        os.remove(txt_filename)

        return archive_filename, f"Report saved to {archive_filename}"

    except Exception as e:
        return None, f"Failed to save report: {str(e)}"

def scan_home_directory(root_path, progress_callback=None):
    files_info = []
    scanned_count = 0
    vulnerable_count = 0
    
    try:
        mime_detector = magic.Magic(mime=True)
    except Exception as e:
        print(f"Warning: python-magic not loaded. {e}")
        mime_detector = None

    for dirpath, dirnames, filenames in os.walk(root_path, topdown=True):
        if is_excluded(dirpath):
            dirnames[:] = []
            continue
            
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            scanned_count += 1
            
            if progress_callback and scanned_count % 10 == 0:
                progress_callback(scanned_count, fpath)

            if not os.path.isfile(fpath) or os.path.islink(fpath):
                continue
            
            try:
                size = os.path.getsize(fpath)
                ext = os.path.splitext(fname)[1].lower()
                
                flag_messages = []
                is_exec = os.access(fpath, os.X_OK)

                if is_exec:
                    flag_messages.append("permissions_executable_bit_set")

                file_signature = "unknown"
                if mime_detector:
                    try:
                        file_signature = mime_detector.from_file(fpath)
                    except: pass
                
                if 'dosexec' in file_signature or 'x-executable' in file_signature:
                     flag_messages.append(f"suspicious_signature:{file_signature}")

                if ext in SUSPICIOUS_EXTENSIONS:
                    flag_messages.append(f"suspicious_extension:{ext}")

                if mime_detector and file_signature in MIME_TO_EXT:
                    if ext not in MIME_TO_EXT[file_signature]:
                        flag_messages.append(f"mismatch_sig({file_signature})_vs_ext({ext})")

                if len(flag_messages) > 0:
                    vulnerable_count += 1
                    files_info.append({
                        "path": fpath,
                        "file_name": fname,
                        "extension": ext,
                        "size_bytes": size,
                        "executable": is_exec,
                        "reasons": "; ".join(flag_messages)
                    })

            except Exception:
                continue

    return scanned_count, vulnerable_count, files_info