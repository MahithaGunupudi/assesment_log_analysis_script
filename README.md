# Log Analysis Script

## Objective
This Python script analyzes web server log files to:
1. Count the number of requests per IP address.
2. Identify the most frequently accessed endpoints.
3. Detect suspicious activity, such as failed login attempts.

## Files in this Repository
- `log_analysis.py`: Python script that performs log analysis.
- `sample.log`: A sample log file used by the script.
- `README.md`: Documentation for using the script.

## Instructions

### 1. Clone the Repository
Clone the repository to your local machine:

```bash
git clone https://github.com/yourusername/assessment_log_analysis_script.git
cd assessment_log_analysis_script
```

### 2. Ensure Python is Installed
Make sure Python 3.x is installed on your system.

### 3. Run the Script

To run the script, navigate to the `code` folder and execute the following command:

```bash
python log_analysis.py
```

### 4. Output
The script will analyze the `sample.log` file and generate a CSV file, `log-analysis-results.csv`, containing:
- **Requests per IP**: A list of IP addresses and their request counts.
- **Most Accessed Endpoint**: The endpoint that was most frequently requested.
- **Suspicious Activity**: IPs with failed login attempts exceeding a threshold (e.g., 10).

## Example Output in CSV Format

```
Requests per IP
IP Address, Request Count
192.168.1.1, 50
203.0.113.5, 30

Most Accessed Endpoint
Endpoint, Access Count
/home, 403

Suspicious Activity
IP Address, Failed Login Count
192.168.1.100, 12
203.0.113.34, 15
```
