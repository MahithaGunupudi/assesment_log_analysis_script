import re
import csv
from collections import Counter, defaultdict

# Input log file
log_file = "sample.log"

# Function to parse log file
def parse_log_file(file_path):
    try:
        with open(file_path, "r") as file:
            logs = file.readlines()
        print(f"Log file loaded successfully: {len(logs)} lines found.")
        return logs
    except FileNotFoundError:
        print("Log file not found. Please check the file path.")
        exit()

# Function to count requests per IP address
def count_requests_per_ip(logs):
    ip_pattern = r"^\d+\.\d+\.\d+\.\d+"
    ip_counts = Counter()
    for log in logs:
        ip_match = re.match(ip_pattern, log)
        if ip_match:
            ip_counts[ip_match.group()] += 1
    return ip_counts

# Function to identify the most frequently accessed endpoint
def most_frequent_endpoint(logs):
    endpoint_pattern = r"\"[A-Z]+\s(\/\S+)"
    endpoint_counts = Counter()
    for log in logs:
        endpoint_match = re.search(endpoint_pattern, log)
        if endpoint_match:
            endpoint_counts[endpoint_match.group(1)] += 1
    most_frequent = endpoint_counts.most_common(1)
    return most_frequent[0] if most_frequent else None

# Function to detect suspicious activity
def detect_suspicious_activity(logs, threshold=10):
    suspicious_ip_counts = defaultdict(int)
    for log in logs:
        if "Invalid credentials" in log or "401" in log:
            ip = re.match(r"^\d+\.\d+\.\d+\.\d+", log).group()
            suspicious_ip_counts[ip] += 1
    flagged_ips = {ip: count for ip, count in suspicious_ip_counts.items() if count > threshold}
    return flagged_ips

# Function to write results to CSV
def write_to_csv(ip_counts, most_frequent_endpoint, suspicious_activity):
    with open("log_analysis_results.csv", "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        # Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])
        
        # Most accessed endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        if most_frequent_endpoint:
            writer.writerow(most_frequent_endpoint)
        
        # Suspicious activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

# Main execution
def main():
    logs = parse_log_file(log_file)
    
    # Count requests per IP
    ip_counts = count_requests_per_ip(logs)
    print("Requests per IP:")
    for ip, count in ip_counts.items():
        print(f"{ip}: {count}")
    
    # Most accessed endpoint
    most_frequent = most_frequent_endpoint(logs)
    if most_frequent:
        print(f"\nMost Frequently Accessed Endpoint: {most_frequent[0]} (Accessed {most_frequent[1]} times)")
    else:
        print("\nNo endpoints found.")
    
    # Detect suspicious activity
    suspicious_activity = detect_suspicious_activity(logs)
    if suspicious_activity:
        print("\nSuspicious Activity Detected:")
        for ip, count in suspicious_activity.items():
            print(f"{ip}: {count} failed login attempts")
    else:
        print("\nNo suspicious activity detected.")
    
    # Write results to CSV
    write_to_csv(ip_counts, most_frequent, suspicious_activity)
    print("\nResults saved to 'log_analysis_results.csv'.")

if _name_ == "_main_":
    main()
