import csv
from collections import Counter

# Counters for data
IP_counts = Counter()
Endpoint_counts = Counter()
Failed_Login_counts = Counter()

FAILED_LOGIN_THRESOLD = 10

# Reading the log file
with open("sample_log.csv", 'r') as infile:
    reader = csv.reader(infile, delimiter=",")
    header = next(reader)  # Read the header (if any)
    for row in reader:
        if row:
                                                     # Count requests per IP
            IP_address = row[0]
            IP_counts[IP_address] += 1

                                                    # Count requests per endpoint
            Request_line = row[2]
            parts = Request_line.split()
            if len(parts) > 1:
                Endpoint = parts[1]
                Endpoint_counts[Endpoint] += 1
            else:
                Endpoint_counts["Unknown"] += 1

                                                     # Count failed login attempts
            HTTP_Status_Code = row[3]
            if HTTP_Status_Code == "401":# Assuming 401 indicates a failed login attempt
                Failed_Login_counts[IP_address] += 1

sorted_ip_counts = sorted(IP_counts.items(), key=lambda item: item[1], reverse=True)

# Identify most accessed endpoint
if Endpoint_counts:
    most_frequent_endpoint, Endpoint_count = Endpoint_counts.most_common(1)[0]
else:
    most_frequent_endpoint, Endpoint_count = "None", 0

# Identify suspicious IPs
suspicious_ips = {}
for ip, count in Failed_Login_counts.items():
    if count > FAILED_LOGIN_THRESOLD:
        suspicious_ips[ip] = count

# Output results in terminal
print("IP_address          Request_Count")
for ip, count in sorted_ip_counts:
    print(f"{ip:<20} {count:>6}")

print(f"\nMost Frequently Accessed Endpoint:")
print(f"{most_frequent_endpoint} (Accessed {Endpoint_count} times)")

if suspicious_ips:
    for ip, count in suspicious_ips.items():
        print("\nSuspicious Activity Detected:")
        print("IP Address           Failed Login Attempts")
        print(f"{ip:<20} {count:>6}")
else:
    print("\nNo suspicious activity detected.")

# Save results to CSV
with open("log_analysis_results.csv", 'w', newline='') as outfile:
    writer = csv.writer(outfile)

    # Requests per IP Section
    writer.writerow(["Requests per IP"])
    writer.writerow(["IP Address".ljust(20), "Request Count".rjust(15)])
    for ip, count in IP_counts.items():
        writer.writerow([ip.ljust(20), str(count).rjust(15)])
    writer.writerow([])  # Blank line for separation

    # Most Accessed Endpoint Section
    writer.writerow(["Most Accessed Endpoint"])
    writer.writerow(["Endpoint".ljust(20), "Access Count".rjust(15)])
    writer.writerow([most_frequent_endpoint.ljust(20), str(Endpoint_count).rjust(15)])
    writer.writerow([])  # Blank line for separation

    # Suspicious Activity Section
    writer.writerow(["Suspicious Activity"])
    writer.writerow(["IP Address".ljust(20), "Failed Login Count".rjust(15)])
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            writer.writerow([ip.ljust(20), str(count).rjust(15)])
    else:
        writer.writerow(["None".ljust(20), "0".rjust(15)])

print("\nResults saved to 'log_analysis_results.csv'.")
