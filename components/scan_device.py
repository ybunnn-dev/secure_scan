import os
import csv
import tarfile
import shutil
import magic  
from datetime import datetime


HOME = os.path.expanduser("~") #home directory of the user
EXCLUDE_DIRS = {"/proc", "/sys", "/dev", "/run", "/var/lib", "/var/run", "/tmp", "/mnt", "/media", "/snap"} #excluding system directories


# for extention flagging
SUSPICIOUS_EXTENSIONS = {
    # High Risk (Executables & Scripts)
    '.exe', '.dll', '.bat', '.cmd', '.sh', '.vbs', '.js', '.ps1', '.elf', '.apk', '.scr', '.wsf', '.wsh', '.php', '.html',
    '.jar', '.docm', '.xlsm', '.pptm',  # macro-enabled
    '.pdf',                             # scripts/exploits
    '.docx', '.doc',                    # word
    '.xlsx', '.xls',                    # excel
    '.pptx', '.ppt',                    # powerpoint
    '.zip', '.rar', '.7z'               # archives 
}


# dangerous file signatures that indicate executables or scripts
DANGEROUS_SIGNATURES = {
    'application/x-dosexec',           # windows EXE/DLL/SCR/COM (4D 5A - "MZ")
    'application/x-executable',        # ELF executables (7F 45 4C 46 - ".ELF")
    'application/x-mach-binary',       # macOS Mach-O (FE ED FA CE)
    'application/x-sharedlib',         # shared libraries (.so files)
    'application/x-msdownload',        # MSI installers (D0 CF 11 E0)
    'text/x-shellscript',              # shell scripts (#! /bin/sh)
    'text/x-python',                   # python scripts (#! /usr/bin/python)
    'text/x-perl',                     # perl scripts
    'application/x-javascript',        # javascript
    'text/javascript',                 # javaScript 
    'application/javascript',          # javaScript 
    'application/x-php',               # PHP scripts
    'text/x-php',                      # PHP scripts 
}


MIME_TO_EXT = {
    # executable type of files portion
    'application/x-dosexec': ['.exe', '.dll', '.com', '.scr'],
    'application/x-executable': ['.elf', '.bin'],
    'application/x-sharedlib': ['.so', '.elf'],
    'application/x-msdownload': ['.msi'],
    
    # images portion
    'image/jpeg': ['.jpg', '.jpeg'],
    'image/png': ['.png'],
    'image/gif': ['.gif'],
    'image/svg+xml': ['.svg'],
    
    # documents portion
    'application/pdf': ['.pdf'],
    'text/plain': ['.txt', '.log', '.md', '.c', '.cpp', '.h', '.json'],
    'application/rtf': ['.rtf'],
    
    # modern office and zip files
    'application/zip': [
        '.zip', '.docx', '.xlsx', '.pptx', '.jar', '.apk', 
        '.docm', '.xlsm', '.pptm', '.odt', '.ods'
    ],
    
    # legacy office (OLE2 Binary Formats)
    'application/msword': ['.doc', '.dot'],
    'application/vnd.ms-excel': ['.xls', '.xlt'],
    'application/vnd.ms-powerpoint': ['.ppt', '.pot', '.pps'],
    'application/vnd.ms-office': ['.doc', '.xls', '.ppt'], 
    
    # specific openXML
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx'],
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'],
    'application/vnd.openxmlformats-officedocument.presentationml.presentation': ['.pptx'],

    # scripts portion
    'text/x-python': ['.py'],
    'text/x-shellscript': ['.sh', '.bash'],
    'application/java-archive': ['.jar'],
    'text/x-perl': ['.pl'],
    'application/x-javascript': ['.js'],
    'text/javascript': ['.js'],
    'application/javascript': ['.js'],
    'application/x-php': ['.php'],
    'text/x-php': ['.php'],
}

SAFE_TEXT_EXTENSIONS = {
    '.conf', '.config', '.ini', '.cfg', '.env', '.yaml', '.yml', 
    '.toml', '.properties', '.rc', '', '.gitignore', '.dockerignore', '.sql', '.te'
}


# destination folders
REPORTS_DIR = "reports"
BACKUP_DIR = "backup"


def check_excluded(path):
    return any(os.path.commonpath([path, e]) == e for e in EXCLUDE_DIRS)


def delete_file(path):
    try:
        if os.path.exists(path):
            os.remove(path)
            return True, "File deleted successfully."
        return False, "File not found."
    except Exception as e:
        return False, str(e)

#this is for archiving the report. we save the report into two paths for redundancy that can support backup
#we also insert the timestamp of the file into a txt file that could enhance the file accuracy. so that the system won't base on the file name.
def save_report_archive(files_info):
    """
    Saves results to 'reports/' and copies to 'backup/'.
    """
    if not files_info:
        return None, "No files to save."

    os.makedirs(REPORTS_DIR, exist_ok=True) #the main archive destination
    os.makedirs(BACKUP_DIR, exist_ok=True) #backup destination

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"scan_report_{timestamp}" #generated filename
    
    csv_filename = f"{base_name}.csv"
    txt_filename = f"{base_name}_meta.txt"
    archive_name = f"{base_name}.tar.gz"
    
    primary_path = os.path.join(REPORTS_DIR, archive_name) #save to the main directory
    backup_path = os.path.join(BACKUP_DIR, archive_name) #save to the backup directory

    try:
        #writing the reports in the csv file
        with open(csv_filename, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=["path", "file_name", "extension", "size_bytes", "executable", "reasons"])
            writer.writeheader()
            for row in files_info:
                clean_row = {k: row[k] for k in writer.fieldnames}
                writer.writerow(clean_row)

        with open(txt_filename, mode='w', encoding='utf-8') as f:
            f.write(f"Scan Report Generated\n")
            f.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")

        with tarfile.open(primary_path, "w:gz") as tar:
            tar.add(csv_filename, arcname=csv_filename)
            tar.add(txt_filename, arcname=txt_filename)

        shutil.copy2(primary_path, backup_path)

        os.remove(csv_filename)
        os.remove(txt_filename)

        return primary_path, f"Report saved to:\n1. {primary_path}\n2. {backup_path}"
    #in case the saving failed, the system will remove the report
    except Exception as e:
        if os.path.exists(csv_filename): os.remove(csv_filename)
        if os.path.exists(txt_filename): os.remove(txt_filename)
        return None, f"Failed to save report: {str(e)}"


#the main scanning function
def scan_start(root_path, progress_callback=None):
    files_info = []
    scanned_count = 0
    vulnerable_count = 0


    try:
        mime_detector = magic.Magic(mime=True)
    except:
        mime_detector = None

    for dirpath, dirnames, filenames in os.walk(root_path, topdown=True):
        if check_excluded(dirpath):
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
                
                check_executable = os.access(fpath, os.X_OK) #checking if it has executable permission

                # 1. checking if the file has executable permission, it will be flagged
                if check_executable: 
                    msgs.append("permissions executable bit set")
                
                # get magic mumber (MIME)
                sig = "unknown"
                if mime_detector:
                    try: sig = mime_detector.from_file(fpath)
                    except: pass
                
                # 2. Flag based on dangerous file signature
                if sig in DANGEROUS_SIGNATURES: 
                    msgs.append(f"dangerous signature:{sig}")
                
                # 3. Suspicious Extension Check
                if ext in SUSPICIOUS_EXTENSIONS: 
                    msgs.append(f"suspicious extension:{ext}")

                # 4. Double Extension Trick Check Like 'peter.pdf.exe'
                parts = fname.split('.')
                if len(parts) > 2:
                    # if it ends in a risky extension but has another extension before it
                    if ext in SUSPICIOUS_EXTENSIONS:
                         msgs.append("possible double extension trick")

                # 5. mismatch check, need to compare extension vs file signature
                if mime_detector and sig in MIME_TO_EXT:
                    if ext not in MIME_TO_EXT[sig]:
                        # will not flag text files with config/benign extensions
                        if sig == 'text/plain' and ext in SAFE_TEXT_EXTENSIONS:
                            pass  # skip flagging
                        else:
                            msgs.append(f"mismatch: signature ({sig}) vs extension({ext})")

                if msgs:
                    vulnerable_count += 1
                    files_info.append({
                        "path": fpath, 
                        "file_name": fname, 
                        "extension": ext, 
                        "size_bytes": size, 
                        "executable": check_executable, 
                        "reasons": "; ".join(msgs)
                    })
            except: continue
            
    return scanned_count, vulnerable_count, files_info
