import os
import csv
import tarfile
import shutil
import magic  
from datetime import datetime

# Configuration
HOME = os.path.expanduser("~")
EXCLUDE_DIRS = {"/proc", "/sys", "/dev", "/run", "/var/lib", "/var/run", "/tmp", "/mnt", "/media", "/snap"}

# [UPDATED] 1. STRICTER Suspicious Extensions List
# Now includes PDF and standard Office Docs because they can contain malicious scripts/macros.
SUSPICIOUS_EXTENSIONS = {
    # High Risk (Executables & Scripts)
    '.exe', '.dll', '.bat', '.cmd', '.sh', '.vbs', '.js', '.ps1', '.elf', '.apk', '.scr', '.wsf', '.wsh',
    # Medium Risk (Documents & Archives that can contain payloads)
    '.jar', '.docm', '.xlsm', '.pptm',  # Macro-enabled
    '.pdf',                             # Scripts/Exploits
    '.docx', '.doc',                    # Word
    '.xlsx', '.xls',                    # Excel
    '.pptx', '.ppt',                    # PowerPoint
    '.zip', '.rar', '.7z'               # Archives (often hide executables)
}

# [UPDATED] 2. Comprehensive Mismatch Logic
# Maps "Magic MIME Types" to allowed extensions.
MIME_TO_EXT = {
    # --- Executables ---
    'application/x-dosexec': ['.exe', '.dll', '.com', '.scr'],
    'application/x-executable': ['.elf', '.bin'],
    'application/x-sharedlib': ['.so', '.elf'],
    
    # --- Images ---
    'image/jpeg': ['.jpg', '.jpeg'],
    'image/png': ['.png'],
    'image/gif': ['.gif'],
    'image/svg+xml': ['.svg'],
    
    # --- Documents ---
    'application/pdf': ['.pdf'],
    'text/plain': ['.txt', '.log', '.md', '.py', '.c', '.cpp', '.h', '.json', '.sh', '.bat', '.ps1'],
    'application/rtf': ['.rtf'],
    
    # --- Modern Office (OpenXML) & Zips ---
    # .docx, .xlsx, .jar, .apk are all technically ZIP files internally.
    'application/zip': [
        '.zip', '.docx', '.xlsx', '.pptx', '.jar', '.apk', 
        '.docm', '.xlsm', '.pptm', '.odt', '.ods'
    ],
    
    # --- Legacy Office (OLE2 Binary Formats) ---
    # These are crucial, otherwise valid .doc files will be flagged as "Mismatch"
    'application/msword': ['.doc', '.dot'],
    'application/vnd.ms-excel': ['.xls', '.xlt'],
    'application/vnd.ms-powerpoint': ['.ppt', '.pot', '.pps'],
    'application/vnd.ms-office': ['.doc', '.xls', '.ppt'], # Generic OLE fallback
    
    # --- Specific OpenXML (Some magic libs get very specific) ---
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'],
    'application/vnd.openxmlformats-officedocument.presentationml.presentation': ['.pptx'],

    # --- Scripts ---
    'text/x-python': ['.py'],
    'text/x-shellscript': ['.sh', '.bash'],
    'application/java-archive': ['.jar'],
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

    os.makedirs(REPORTS_DIR, exist_ok=True)
    os.makedirs(BACKUP_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"scan_report_{timestamp}"
    
    csv_filename = f"{base_name}.csv"
    txt_filename = f"{base_name}_meta.txt"
    archive_name = f"{base_name}.tar.gz"
    
    primary_path = os.path.join(REPORTS_DIR, archive_name)
    backup_path = os.path.join(BACKUP_DIR, archive_name)

    try:
        with open(csv_filename, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=["path", "file_name", "extension", "size_bytes", "executable", "reasons"])
            writer.writeheader()
            for row in files_info:
                clean_row = {k: row[k] for k in writer.fieldnames}
                writer.writerow(clean_row)

        with open(txt_filename, mode='w', encoding='utf-8') as f:
            f.write(f"Scan Report Generated\n")
            f.write(f"=====================\n")
            f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Suspicious Files: {len(files_info)}\n")
            f.write(f"Scanned Directory: {HOME}\n")

        with tarfile.open(primary_path, "w:gz") as tar:
            tar.add(csv_filename, arcname=csv_filename)
            tar.add(txt_filename, arcname=txt_filename)

        shutil.copy2(primary_path, backup_path)

        os.remove(csv_filename)
        os.remove(txt_filename)

        return primary_path, f"Report saved to:\n1. {primary_path}\n2. {backup_path}"

    except Exception as e:
        if os.path.exists(csv_filename): os.remove(csv_filename)
        if os.path.exists(txt_filename): os.remove(txt_filename)
        return None, f"Failed to save report: {str(e)}"

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

                # 1. Executable Bit Check
                if is_exec: 
                    msgs.append("permissions_executable_bit_set")
                
                # Get Magic Number (MIME)
                sig = "unknown"
                if mime_detector:
                    try: sig = mime_detector.from_file(fpath)
                    except: pass
                
                # 2. Suspicious Signature Check (Executables lurking in data folders)
                if 'dosexec' in sig or 'x-executable' in sig: 
                    msgs.append(f"suspicious_signature:{sig}")
                
                # 3. Suspicious Extension Check (Now includes macros/scr/jar)
                if ext in SUSPICIOUS_EXTENSIONS: 
                    msgs.append(f"suspicious_extension:{ext}")

                # [NEW] 4. Double Extension Trick Check
                # Example: "invoice.pdf.exe" -> The OS hides .exe, user sees .pdf
                parts = fname.split('.')
                if len(parts) > 2:
                    # If it ends in a risky extension but has another extension before it
                    if ext in SUSPICIOUS_EXTENSIONS:
                         msgs.append("possible_double_extension_trick")

                # 5. Mismatch Check (Signature vs Extension)
                if mime_detector and sig in MIME_TO_EXT:
                    # We check if the current extension is NOT in the allowed list for this signature
                    if ext not in MIME_TO_EXT[sig]:
                        msgs.append(f"mismatch_sig({sig})_vs_ext({ext})")

                if msgs:
                    vulnerable_count += 1
                    files_info.append({
                        "path": fpath, 
                        "file_name": fname, 
                        "extension": ext, 
                        "size_bytes": size, 
                        "executable": is_exec, 
                        "reasons": "; ".join(msgs)
                    })
            except: continue
            
    return scanned_count, vulnerable_count, files_info