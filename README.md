# Log File Analyzer

## Project Description
This script analyzes server log files to extract key insights, such as:
- Requests per IP address (sorted in descending order).
- The most frequently accessed endpoint and its request count.
- Suspicious activities, such as repeated failed login attempts.

The results are saved in a CSV file (`log_analysis_results.csv`) and also displayed in the terminal.

---

## Features
1. **Requests Per IP Address**: Counts the number of requests made by each IP and sorts them in descending order.
2. **Most Frequently Accessed Endpoint**: Identifies the most accessed endpoint and its total requests.
3. **Suspicious Activity Detection**: Detects IP addresses with failed login attempts (HTTP status code `401`) exceeding a specified threshold.
4. **Output**:
   - Saves the results to a CSV file.
   - Displays the analysis in the terminal for quick review.

---

## How It Works
1. **Log Parsing**:
   - Extracts the IP address, endpoint, and status code from each log entry using regular expressions.
   
2. **Data Analysis**:
   - **Request Count by IP**: Counts the total requests per IP.
   - **Top Endpoint**: Identifies the most accessed endpoint and its count.
   - **Suspicious IP Detection**: Tracks failed login attempts and flags IPs exceeding the defined threshold.

3. **Output Generation**:
   - **Terminal**: Prints all results in a structured format.
   - **CSV File**: Saves the results into a well-organized CSV file.

---

## How to Use
1. **Setup**:
   - Place your log file (e.g., `sample.log`) in the same directory as the script.

2. **Run the Script**:
   - Execute the script in a Python environment:
     ```bash
     python log_analyzer.py
     ```
   - Replace `log_analyzer.py` with the actual name of the script file.

3. **Results**:
   - View results in the terminal.
   - Check the generated `log_analysis_results.csv` for saved output.

---

## Example Output
### Terminal Output
```plaintext
Requests per IP Address:
IP Address         Request Count
192.168.1.1        100
203.0.113.5        50
198.51.100.7       30

Most Frequently Accessed Endpoint:
/login accessed 500 times

Suspicious Activity Detected:
IP Address         Failed Login Attempts
192.168.1.1        3
203.0.113.5        2

Results saved to 'log_analysis_results.csv'.
