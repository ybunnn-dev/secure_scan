import os
import csv
import tarfile
import shutil  # Added for copying to backup
import magic  
from datetime import datetime

# ... (Previous constants like HOME, EXCLUDE_DIRS remain the same) ...
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

# Define your output folders
REPORTS_DIR = "reports"
BACKUP_DIR = "backup"

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
    Saves results to 'reports/' and copies to 'backup/'.
    """
    if not files_info:
        return None, "No files to save."

    # 1. Ensure directories exist
    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"scan_report_{timestamp}"
    
    # Temporary filenames (created in current dir, then deleted)
    csv_filename = f"{base_name}.csv"
    txt_filename = f"{base_name}_meta.txt"
    archive_name = f"{base_name}.tar.gz"
    
    # Final Destination Paths
    primary_path = os.path.join(REPORTS_DIR, archive_name)
    backup_path = os.path.join(BACKUP_DIR, archive_name)

    try:
        # 2. Create CSV File
        with open(csv_filename, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=["path", "file_name", "extension", "size_bytes", "executable", "reasons"])
            writer.writeheader()
            for row in files_info:
                clean_row = {k: row[k] for k in writer.fieldnames}
                writer.writerow(clean_row)

        # 3. Create Text File with Timestamp
        with open(txt_filename, mode='w', encoding='utf-8') as f:
            f.write(f"Scan Report Generated\n")
            f.write(f"=====================\n")
            f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Suspicious Files: {len(files_info)}\n")
            f.write(f"Scanned Directory: {HOME}\n")

        # 4. Compress into .tar.gz (directly into the reports folder)
        with tarfile.open(primary_path, "w:gz") as tar:
            tar.add(csv_filename, arcname=csv_filename)
            tar.add(txt_filename, arcname=txt_filename)

        # 5. Copy to Backup folder
        shutil.copy2(primary_path, backup_path)

        # 6. Cleanup temporary source files
        os.remove(csv_filename)
        os.remove(txt_filename)

        return primary_path, f"Report saved to:\n1. {primary_path}\n2. {backup_path}"

    except Exception as e:
        # Cleanup if something failed
        if os.path.exists(csv_filename): os.remove(csv_filename)
        if os.path.exists(txt_filename): os.remove(txt_filename)
        return None, f"Failed to save report: {str(e)}"

# ... (The scan_home_directory function remains unchanged) ...
def scan_home_directory(root_path, progress_callback=None):
    files_info = []
    scanned_count = 0
    vulnerable_count = 0
    try:
        mime_detector = magic.Magic(mime=True)
    except:
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
            if not os.path.isfile(fpath) or os.path.islink(fpath): continue
            try:
                size = os.path.getsize(fpath)
                ext = os.path.splitext(fname)[1].lower()
                msgs = []
                is_exec = os.access(fpath, os.X_OK)
                if is_exec: msgs.append("permissions_executable_bit_set")
                sig = "unknown"
                if mime_detector:
                    try: sig = mime_detector.from_file(fpath)
                    except: pass
                if 'dosexec' in sig or 'x-executable' in sig: msgs.append(f"suspicious_signature:{sig}")
                if ext in SUSPICIOUS_EXTENSIONS: msgs.append(f"suspicious_extension:{ext}")
                if mime_detector and sig in MIME_TO_EXT and ext not in MIME_TO_EXT[sig]:
                    msgs.append(f"mismatch_sig({sig})_vs_ext({ext})")
                if msgs:
                    vulnerable_count += 1
                    files_info.append({"path": fpath, "file_name": fname, "extension": ext, "size_bytes": size, "executable": is_exec, "reasons": "; ".join(msgs)})
            except: continue
    return scanned_count, vulnerable_count, files_info