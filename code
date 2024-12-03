import re
import csv
from collections import Counter

# 1. Parse the log file
log_file = 'sample.log'
with open(log_file, 'r') as file:
    logs = file.readlines()

# 2. Count requests per IP
ip_pattern = r'^\d+\.\d+\.\d+\.\d+'
ip_counts = Counter(re.match(ip_pattern, log).group() for log in logs if re.match(ip_pattern, log))

# 3. Identify most accessed endpoint
endpoint_pattern = r'"(?:GET|POST) (\S+)'
endpoints = Counter(re.search(endpoint_pattern, log).group(1) for log in logs if re.search(endpoint_pattern, log))
most_accessed = endpoints.most_common(1)[0]

# 4. Detect suspicious activity
failed_logins = Counter(re.match(ip_pattern, log).group() for log in logs if '401' in log or 'Invalid credentials' in log)
suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > 10}

# 5. Output results to CSV
output_file = 'log-analysis-results.csv'
with open(output_file, 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(["Requests per IP"])
    writer.writerow(["IP Address", "Request Count"])
    writer.writerows(ip_counts.items())

    writer.writerow([])
    writer.writerow(["Most Accessed Endpoint"])
    writer.writerow(["Endpoint", "Access Count"])
    writer.writerow([most_accessed[0], most_accessed[1]])

    writer.writerow([])
    writer.writerow(["Suspicious Activity"])
    writer.writerow(["IP Address", "Failed Login Count"])
    writer.writerows(suspicious_ips.items())
