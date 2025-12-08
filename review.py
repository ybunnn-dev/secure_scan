# review.py
import os
import glob
import tarfile
import csv

RESULTS_DIR = "results"

REPORTS_DIR = "reports"  # Define the folder

def get_available_archives():
    archives = []
    # UPDATE: Now look inside the REPORTS_DIR
    search_path = os.path.join(REPORTS_DIR, "scan_report_*.tar.gz")
    
    for archive_path in glob.glob(search_path):
        display_time = "Unknown Date"
        try:
            with tarfile.open(archive_path, "r:gz") as tar:
                for member in tar.getmembers():
                    if member.name.endswith("_meta.txt"):
                        f = tar.extractfile(member)
                        content = f.read().decode('utf-8')
                        for line in content.splitlines():
                            if line.startswith("Timestamp:"):
                                display_time = line.split("Timestamp:")[1].strip()
                                break
        except:
            display_time = "Error reading archive"
        
        archives.append({
            "filename": archive_path,
            "display_time": display_time
        })
    
    # Sort newest file first
    archives.sort(key=lambda x: x['filename'], reverse=True)
    return archives

def load_archive_to_results(archive_filename):
    """
    Extracts CSV from archive to 'results/' and reads it.
    """
    if not os.path.exists(RESULTS_DIR):
        os.makedirs(RESULTS_DIR)

    # Clear old results
    for f in os.listdir(RESULTS_DIR):
        if f.endswith(".csv"):
            os.remove(os.path.join(RESULTS_DIR, f))

    extracted_csv_path = None

    try:
        with tarfile.open(archive_filename, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith(".csv"):
                    tar.extract(member, path=RESULTS_DIR)
                    extracted_csv_path = os.path.join(RESULTS_DIR, member.name)
        
        if not extracted_csv_path:
            return []

        data = []
        with open(extracted_csv_path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Type conversion for GUI
                row['size_bytes'] = int(row['size_bytes'])
                row['executable'] = (row['executable'] == 'True')
                data.append(row)
        return data

    except Exception as e:
        print(f"Error: {e}")
        return []