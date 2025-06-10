import re
# Provides a dictionary that returns a default value when a key is missing
from collections import defaultdict

# Configuration Variables

# Patterns to match failed login attempts from a log files.
# These use regex to extract IP addresses from common failure messages.
FAILED_LOGIN_PATTERNS = [
    r"Failed password for .* from (\d{1,3}(?:\.\d{1,3}){3})", # Pattern for SSH-style login failures
    r"Failed login from (\d{1,3}(?:\.\d{1,3}){3})" # General login failure pattern
]

# List of keywords considered suspicious in log entries
SUSPICIOUS_KEYWORD = ["error", "denied", "unauthorized", "invalid"]

# Number of failed attempts before flagging potential brute-force activity
BRUTE_FORCE_THRESHOLD = 5

def analyze_log(log_file_path):
    """Analyzes a log file for failed login attempts and suspicious entries."""

    # Stores number of failed logins per IP address
    failed_logins = defaultdict(int)

    # Stores suspicious lines (not just failed logins)
    suspicious_lines = []

    total_lines = 0 # Counter for how many lines we've read

    print(f"\n Analyzing log file: {log_file_path}")

    try:
        # Open and read the log file line by line
        with open(log_file_path, "r") as f:
            for line in f:
                total_lines += 1
                line_lower = line.lower() # Convert to lowercase for keyword matching

                # Loop through the failed login regex patterns
                for pattern in FAILED_LOGIN_PATTERNS:
                    match = re.search(pattern, line, re.IGNORECASE)
                    if match:
                        ip = match.group(1) # Extract IP address from match
                        failed_logins[ip] += 1 # Count how many times this IP failed

                # Check for general suspicious keywords like "denied" or "unauthorized"
                if any(keyword in line_lower for keyword in SUSPICIOUS_KEYWORD):
                    suspicious_lines.append(line.strip()) # Save the full suspicious line
        
        # Generate And Print The Report
        
        print(f"\n--- Log Analysis Report for '{log_file_path}' ---")
        print(f"Total lines processed: {total_lines}")

        # Display failed login attempts by IP
        print("\n Repeated Failed Login Attempts:")
        if failed_logins:
            for ip, count in sorted(failed_logins.items(), key=lambda item: item[1], reverse=True):
                print(f" {ip}: {count} failed attempt(s)")
            
        else:
            print(" No failed login attempts detected.")

        # Show any IPs that crossed the brute-force threshold
        print("\n Potential Brute-Force IPs (>{} failed logins):".format(BRUTE_FORCE_THRESHOLD))
        any_brute_force = False
        for ip, count in failed_logins.items():
            if count > BRUTE_FORCE_THRESHOLD:
                print(f" Alert: {ip} - {count} failed attempts")
                any_brute_force = True
        if not any_brute_force:
            print(" No brute-force behavior detected.")

        # Show a few other suspicious entries (besides login failures)
        print("\n Other Suspicious Log Entries:")
        if suspicious_lines:
            for entry in suspicious_lines[:10]: # Show only first 10 to keep it readable
                print(f" {entry}")
        else:
            print(" No Other suspicious entries found.")

        # Save the Report to a File

        with open("log_analysis_report.txt", "w") as out:
            out.write("Log Analysis Report\n")
            out.write("===================\n")
            out.write(f"Processed file: {log_file_path}\n")
            out.write(f"Total lines: {total_lines}\n\n")

            out.write("Failed Login Attempts:\n")
            for ip, count in failed_logins.items():
                out.write(f"{ip}: {count} attempts\n")
            
            out.write("\nPotential Brute-Force IPs:\n")
            for ip, count in failed_logins.items():
                if count > BRUTE_FORCE_THRESHOLD:
                    out.write(f"ALERT: {ip} - {count} failed attempts\n")
            
            out.write("\nSuspicious Entries:\n")
            for entry in suspicious_lines:
                out.write(f"{entry}\n")
            
        print("\n Report saved to 'log_analysis_report.txt'")

    except FileNotFoundError:
        print(f"Error: Log file not found at '{log_file_path}'")
    except Exception as e:
        print(f"An error occurred during analysis: {e}")

# Dummy Log to Test
def create_dummy_log():
    """Creates a sample log file called 'example.log' for testing the script."""
    dummy_log_content = """
    INFO: User 'john.doe' logged in successfully from 192.168.1.10.
    ERROR: Failed login from 10.0.0.5. Invalid password.
    INFO: System startup complete.
    ERROR: Failed login from 10.0.0.5. Invalid password.
    WARNING: Disk space low on /dev/sda1.
    INFO: User 'jane.smith' logged in successfully from 172.16.0.20.
    ERROR: Failed login from 10.0.0.5. Invalid password.
    ERROR: Failed login from 10.0.0.5. Invalid password.
    ERROR: Failed login from 10.0.0.5. Invalid password.
    ERROR: Failed login from 192.168.1.100. Unknown user.
    INFO: Application data saved.
    ERROR: Failed login from 10.0.0.5. Invalid password.
    """
    with open("example.log", "w") as f:
        f.write(dummy_log_content.strip())
    print("Created dummy log file: 'example.log'")

def main():
    """ Main entry point of the script."""
    print("Simple Log Analyzer")
    print("===================")

    # Ask the user to enter a log file path, or leave it blank to use the dummy one
    log_path = input("Enter the path to the log file or press Enter to use dummy log: ").strip()

    # If the user didn't enter a path, generate and use the dummy file
    if not log_path:
        create_dummy_log()
        log_path = "example.log"
    
    analyze_log(log_path)

if __name__ == "__main__":
    main()
