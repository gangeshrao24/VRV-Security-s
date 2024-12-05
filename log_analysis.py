import re
import csv
from collections import defaultdict, Counter
import time

# Constants
LOG_FILE = "sample.log"
CSV_FILE = "log_analysis_results.csv"
FAILED_LOGIN_THRESHOLD = 10

# Helper function to extract data from logs
def parse_log_file(file_path):
    with open(file_path, 'r') as file:
        logs = file.readlines()
    return logs

# Function to count requests per IP
def count_requests_per_ip(logs):
    ip_counts = defaultdict(int)
    for log in logs:
        match = re.match(r'(\d+\.\d+\.\d+\.\d+)', log)
        if match:
            ip_counts[match.group(1)] += 1
    return dict(sorted(ip_counts.items(), key=lambda x: x[1], reverse=True))

# Function to find the most frequently accessed endpoint
def most_frequent_endpoint(logs):
    endpoint_counts = Counter()
    for log in logs:
        match = re.search(r'"(?:GET|POST|PUT|DELETE|OPTIONS|HEAD) (\S+)', log)
        if match:
            endpoint_counts[match.group(1)] += 1
    most_common = endpoint_counts.most_common(1)
    return most_common[0] if most_common else None

# Function to detect suspicious activity
def detect_suspicious_activity(logs):
    failed_login_attempts = defaultdict(int)
    for log in logs:
        if "401" in log or "Invalid credentials" in log:
            match = re.match(r'(\d+\.\d+\.\d+\.\d+)', log)
            if match:
                failed_login_attempts[match.group(1)] += 1
    return {ip: count for ip, count in failed_login_attempts.items() if count > FAILED_LOGIN_THRESHOLD}

# Function to save results to CSV
def save_to_csv(ip_requests, most_accessed, suspicious_ips):
    with open(CSV_FILE, mode='w', newline='') as file:
        writer = csv.writer(file)

        # Write Requests per IP
        writer.writerow(["Requests per IP"])
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests.items():
            writer.writerow([ip, count])

        writer.writerow([])  # Blank row for separation

        # Write Most Accessed Endpoint
        writer.writerow(["Most Accessed Endpoint"])
        writer.writerow(["Endpoint", "Access Count"])
        if most_accessed:
            writer.writerow(most_accessed)

        writer.writerow([])  # Blank row for separation

        # Write Suspicious Activity
        writer.writerow(["Suspicious Activity"])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

# Main execution function
def main():
    logs = parse_log_file(LOG_FILE)

    # Analyze logs
    ip_requests = count_requests_per_ip(logs)
    most_accessed = most_frequent_endpoint(logs)
    suspicious_ips = detect_suspicious_activity(logs)

    # Display results
    print("Requests per IP Address:")
    for ip, count in ip_requests.items():
        print(f"{ip: <20} {count}")

    if most_accessed:
        print("\nMost Frequently Accessed Endpoint:")
        print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_ips.items():
        print(f"{ip: <20} {count}")

    # Save to CSV
    save_to_csv(ip_requests, most_accessed, suspicious_ips)
    print(f"\nResults saved to {CSV_FILE}")

# Run the script
if __name__ == "__main__":
    t1 = time.time()
    main()
    t2 = time.time()
    print("Execution Time = ", t2 - t1, "sec")