import re
import csv
from collections import defaultdict, Counter

# Configuration to handle failed login attempts and the threshold
FAILED_LOGIN_THRESHOLD = 2
ENDPOINT_PATTERN = r'"[A-Z]+\s([^\s]+)\s'  # Adjust if endpoint format changes

def parse_log_line(line):
    """Parse the log line to extract relevant information (IP, status code, endpoint)."""
    ip = None
    endpoint = None
    status_code = None
    match_ip = re.match(r"(\d+\.\d+\.\d+\.\d+)", line)
    if match_ip:
        ip = match_ip.group(1)
    
    match_endpoint = re.search(ENDPOINT_PATTERN, line)
    if match_endpoint:
        endpoint = match_endpoint.group(1)
    
    match_status = re.search(r'"\s(\d{3})\s', line)
    if match_status:
        status_code = match_status.group(1)
    
    return ip, endpoint, status_code

def detect_suspicious_activity(log_lines):
    """Detect IPs with suspicious behavior, such as multiple failed login attempts."""
    failed_attempts = defaultdict(int)
    for line in log_lines:
        ip, endpoint, status_code = parse_log_line(line)
        if status_code == "401":  # Assuming 401 indicates failed login
            failed_attempts[ip] += 1
    suspicious_ips = {ip: count for ip, count in failed_attempts.items() if count > FAILED_LOGIN_THRESHOLD}
    return suspicious_ips

def analyze_logs(log_lines):
    """Analyze logs to gather request counts, endpoints, and suspicious activities."""
    ip_counter = Counter()
    endpoint_counter = Counter()

    # Analyze the log lines
    for line in log_lines:
        ip, endpoint, status_code = parse_log_line(line)
        if ip:
            ip_counter[ip] += 1
        if endpoint:
            endpoint_counter[endpoint] += 1

    # Detect suspicious activity
    suspicious_ips = detect_suspicious_activity(log_lines)

    # Get the most frequently accessed endpoint
    most_frequented_endpoint, access_count = endpoint_counter.most_common(1)[0] if endpoint_counter else (None, 0)

    return ip_counter, most_frequented_endpoint, access_count, suspicious_ips

def save_to_csv_and_display(ip_counter, most_frequented_endpoint, access_count, suspicious_ips):
    """Save the analysis results to a CSV file and display them in the terminal."""
    
    # Sort IP requests in descending order by count
    sorted_ip_data = sorted(ip_counter.items(), key=lambda x: x[1], reverse=True)
    
    suspicious_data = [(ip, count) for ip, count in suspicious_ips.items()]

    # Save results to CSV
    with open("log_analysis_results.csv", "w", newline="") as file:
        writer = csv.writer(file, delimiter=',')
        
        # Requests per IP Address
        writer.writerow(["Requests per IP Address"])
        writer.writerow(["IP Address", "Request Count"])
        writer.writerows(sorted_ip_data)

        writer.writerow([])  # Empty row between sections
        
        # Most Frequently Accessed Endpoint
        writer.writerow(["Most Frequently Accessed Endpoint"])
        writer.writerow([most_frequented_endpoint, f"Accessed {access_count} times"])
        
        writer.writerow([])  # Empty row between sections
        
        # Suspicious Activity Detected
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        writer.writerows(suspicious_data)

    # Display results in the terminal
    print("\nRequests per IP Address:")
    print(f"{'IP Address':<20}{'Request Count'}")
    for ip, count in sorted_ip_data:
        print(f"{ip:<20}{count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_frequented_endpoint} accessed {access_count} times")

    print("\nSuspicious Activity Detected:")
    print(f"{'IP Address':<20}{'Failed Login Attempts'}")
    for ip, count in suspicious_data:
        print(f"{ip:<20}{count}")

    print("\nResults saved to 'log_analysis_results.csv'.")

def process_log_file(file_path):
    """Read the log file, process it, and generate analysis."""
    with open(file_path, "r") as file:
        log_lines = file.readlines()

    ip_counter, most_frequented_endpoint, access_count, suspicious_ips = analyze_logs(log_lines)
    save_to_csv_and_display(ip_counter, most_frequented_endpoint, access_count, suspicious_ips)

# Call process_log_file with the path to your log file.
process_log_file("sample.log")
