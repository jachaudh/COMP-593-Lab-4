import sys
import re
import pandas as pd


def get_log_file_path(param_index):
    if len(sys.argv) <= param_index:
        print("Error: Log file path not provided.")
        sys.exit(1)
    log_file_path = sys.argv[param_index]
    if not os.path.exists(log_file_path):
        print("Error: Log file does not exist.")
        sys.exit(1)
    return log_file_path

def filter_log_by_regex(log_file_path, regex):
    matching_records = []
    with open(log_file_path, 'r') as file:
        for line in file:
            if re.search(regex, line, re.IGNORECASE):
                matching_records.append(line.strip())
    return matching_records

def extract_data_to_dataframe(log_file_path, regex):
    matching_records = filter_log_by_regex(log_file_path, regex)
    extracted_data = []
    for record in matching_records:
        match = re.match(regex, record)
        if match:
            extracted_data.append(match.groups())
    columns = ['Source IP', 'Destination IP', 'Length']
    df = pd.DataFrame(extracted_data, columns=columns)
    return df

def tally_traffic_by_port(log_file_path):
    port_counts = {}
    with open(log_file_path, 'r') as file:
        for line in file:
            match = re.search(r'DPT=(\d+)', line)
            if match:
                port = match.group(1)
                port_counts[port] = port_counts.get(port, 0) + 1
    return port_counts


def generate_port_report(log_file_path, destination_port):
    regex = f'DPT={destination_port}'
    df = extract_data_to_dataframe(log_file_path, regex)
    report_filename = f'destination_port_{destination_port}_report.csv'
    df.to_csv(report_filename, index=False)

def generate_invalid_user_report(log_file_path):
    regex = r'Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)'
    df = extract_data_to_dataframe(log_file_path, regex)
    report_filename = 'invalid_users.csv'
    df.to_csv(report_filename, index=False)

def extract_and_save_source_ip_records(log_file_path, source_ip):
    regex = f'SRC={re.escape(source_ip.replace(".", "\\."))}'
    matching_records = filter_log_by_regex(log_file_path, regex)
    report_filename = f'source_ip_{source_ip.replace(".", "_")}.txt'
    with open(report_filename, 'w') as file:
        for record in matching_records:
            file.write(record + '\n')

def main():
    if len(sys.argv) < 2:
        print("Usage: python script.py log_file_path")
        sys.exit(1)
    
    log_file_path = get_log_file_path(1)
    port_counts = tally_traffic_by_port(log_file_path)
    
    for port, count in port_counts.items():
        if count >= 100:
            generate_port_report(log_file_path, port)
    
    generate_invalid_user_report(log_file_path)
    extract_and_save_source_ip_records(log_file_path, '220.195.35.40')

if __name__ == "__main__":
    main()
