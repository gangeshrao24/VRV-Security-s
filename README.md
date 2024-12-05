# VRV-Security-s
Python script for log analysis as part of VRV Security's assignment.

### **Project Documentation: Log File Analysis and Suspicious Activity Detection**

#### **1. Project Overview**

This Python-based log analysis tool processes web server log files to extract critical information, including request counts by IP address, the most frequently accessed endpoints, and potential security threats like brute-force login attempts. It serves as a practical solution for cybersecurity tasks, offering both visual insights and detailed CSV output.

#### **2. Features**

The tool offers the following capabilities:
1. **Request Count by IP**: Tracks the number of requests made by each unique IP address.
2. **Frequently Accessed Endpoint Identification**: Identifies the most frequently accessed resource (URL or endpoint) in the logs.
3. **Suspicious Activity Detection**: Flags IPs with excessive failed login attempts (status code `401` or "Invalid credentials").
4. **Output Results**: Displays results in the terminal and saves them to a structured CSV file.

#### **3. Functional Requirements**

1. **Count Requests per IP**:
   - Extract and count requests for each IP.
   - Display results sorted by request count.

2. **Identify Frequently Accessed Endpoints**:
   - Parse log entries to extract endpoints.
   - Identify the most accessed endpoint and display its access count.

3. **Detect Suspicious Activity**:
   - Search for failed login attempts.
   - Flag IPs exceeding a configurable threshold for failed attempts (default: 10).

4. **Output Results**:
   - Display the findings in the terminal.
   - Save results to a CSV file (`log_analysis_results.csv`) with sections for:
     - **Requests per IP**: IP Address, Request Count.
     - **Most Accessed Endpoint**: Endpoint, Access Count.
     - **Suspicious Activity**: IP Address, Failed Login Count.

#### **4. Non-Functional Requirements**

1. **Performance**:
   - Processes logs efficiently, with results in seconds for up to tens of thousands of entries.
   - Designed for low memory consumption, ensuring efficient handling of large files.

2. **Scalability**:
   - Can process larger log files without significant delays.
   - Extendable for distributed processing in future iterations.

3. **User Experience**:
   - Terminal output is clear and formatted for readability.
   - CSV output enables further offline analysis.

#### **5. Input and Output**

**Input**:  
- A log file (e.g., `sample.log`) containing web server entries in standard formats, including IP addresses, timestamps, request methods, endpoints, and status codes.

**Output**:  
- **Terminal**: 
  - Request counts by IP.
  - The most accessed endpoint and its frequency.
  - IPs flagged for suspicious activity with their failed login counts.
- **CSV File**:
  - Structured sections for Requests per IP, Most Accessed Endpoint, and Suspicious Activity.

#### **6. Script Structure**

1. **`log_analysis.py`**:  
   - Implements all functions for data extraction, analysis, and output generation.
   - Includes helper functions for log parsing, request counting, endpoint identification, and suspicious activity detection.

#### **7. Code Flow**

1. **Log File Parsing**:
   - Reads the log file line by line.
   - Extracts key information (IP address, endpoint, status code) using regular expressions.

2. **Analysis Steps**:
   - **Request Counting**: Counts requests for each IP using a dictionary.
   - **Endpoint Analysis**: Tracks endpoint occurrences to find the most accessed resource.
   - **Suspicious Activity**: Flags IPs with excessive failed login attempts based on a threshold.

3. **Result Generation**:
   - Displays results in the terminal.
   - Writes findings to a structured CSV file.

#### **8. Sample Usage**

```bash
$ python log_analysis.py
```

#### **9. Performance Considerations**

- **Execution Time**: 
  - Processes files with thousands of lines in seconds.
- **Memory Efficiency**: 
  - Uses lightweight data structures (`defaultdict`, `Counter`) to minimize resource consumption.

#### **10. Limitations**

- Assumes logs follow a standard format.
- Suspicious activity detection relies solely on failed login counts, which may miss more complex attack patterns.

#### **11. Future Enhancements**

1. **Real-time Analysis**: Integrate live monitoring for on-the-fly threat detection.
2. **Advanced Detection**: Implement machine learning models to identify nuanced attack patterns.
3. **Data Visualization**: Provide graphs and dashboards for trend analysis.

#### **12. Conclusion**

This tool offers a comprehensive approach to log file analysis for cybersecurity needs. By automating data extraction, analysis, and reporting, it provides actionable insights to enhance system security and monitor web server activity effectively.
