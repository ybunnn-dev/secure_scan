# review.py
import os
import glob
import tarfile
import csv

RESULTS_DIR = "results" # the directory where the current csv report is going to be placed
REPORTS_DIR = "reports" # the directory of the archives

#function to get the archive
def get_available_archives():
    archives = []
    search_path = os.path.join(REPORTS_DIR, "scan_report_*.tar.gz")
    
    for archive_path in glob.glob(search_path):
        display_time = "Unknown Date"
        try:
            # the system will take the content of the txt file in every archive an find the "Timestamp"
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
        
        #return the file name and timestamp for the options
        archives.append({
            "filename": archive_path,
            "display_time": display_time
        })
    
    # sort newest file first for the options
    archives.sort(key=lambda x: x['filename'], reverse=True)
    return archives

#preparing the archived report
def load_archive_to_results(archive_filename):
    # extracts CSV from archive to results directory and reads it.
    if not os.path.exists(RESULTS_DIR):
        os.makedirs(RESULTS_DIR)

    # the current report must be removed first
    for f in os.listdir(RESULTS_DIR):
        if f.endswith(".csv"):
            os.remove(os.path.join(RESULTS_DIR, f))

    extracted_csv_path = None

    try:
        with tarfile.open(archive_filename, "r:gz") as tar:
            for member in tar.getmembers():
                if member.name.endswith(".csv"):
                    # extract the csv file only to the results directory
                    tar.extract(member, path=RESULTS_DIR)
                    extracted_csv_path = os.path.join(RESULTS_DIR, member.name)
                    break # stop after finding the csv
        
        if not extracted_csv_path or not os.path.exists(extracted_csv_path):
            return []

        data = []
        with open(extracted_csv_path, mode='r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            for row in reader:

                row['size_bytes'] = int(row.get('size_bytes', 0))
                row['executable'] = (str(row.get('executable', 'False')) == 'True')
                data.append(row)
        return data

    except Exception as e:
        print(f"Error loading archive: {e}")
        return []