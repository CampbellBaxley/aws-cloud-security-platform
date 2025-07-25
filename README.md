# My Cloud Project

This repository contains the code and configuration for my cloud project.

## Initial Setup Documentation

### AWS Account and IAM Configuration
- An AWS account has been created for this project, leveraging the AWS Free Tier.
- The **AWS Root Account has been secured by enabling Multi-Factor Authentication (MFA)**. This account will be reserved only for critical, non-routine tasks.
- A thorough understanding of **IAM concepts (users, groups, roles, and policies)** was established, with a strong focus on the **Principle of Least Privilege**.
- A **dedicated IAM user (`Campbell IAM`)** has been created for daily operational work, ensuring the root account is not used for routine tasks.
    - For initial setup convenience, the `AdministratorAccess` managed policy was **temporarily attached** to `Campbell IAM`.
    - **Crucial next step:** Permissions for `Campbell IAM` will be **refined** in the future to strictly adhere to the Principle of Least Privilege.
    - Programmatic access keys (Access Key ID and Secret Access Key) were generated for `Campbell IAM` for API and CLI interaction.
    - These access keys were **immediately downloaded and stored securely locally** (e.g., in `~/.aws/credentials`), strictly following the operational security best practice of **never storing keys directly in code**.
    - **MFA has been enabled** for console access for the `Campbell IAM` user, adding an essential layer of security.

### Git Repository Setup
This project utilizes Git for robust version control and is hosted on GitHub.
1.  A **local Git repository was initialized** (`git init`) within the project directory.
2.  An initial `README.md` file was created to serve as project documentation.
3.  The local repository was successfully **connected to a new, empty remote GitHub repository** (`git remote add origin <repo_url>`).
4.  An **initial commit** (`git commit -m "Initial commit..."`) was made, marking the project's commencement.
5.  The committed changes were successfully **pushed to the remote GitHub repository** (`git push -u origin main`).
6.  This `README.md` file has been updated to document all AWS account creation, IAM user setup, and initial Git configuration steps, emphasizing secure practices from inception.

---

## Today's Summary (Day 1: AWS Account Setup & Secure IAM Configuration)

Today, the foundational security and version control aspects of the project were established, focusing on secure access and best practices:

* **AWS Account Secured:** Successfully signed up for an AWS account and immediately secured the root account by enabling MFA.
* **Secure IAM User Created:** A dedicated IAM user (`Campbell IAM`) was set up for daily operations, temporarily granted `AdministratorAccess` with the explicit intent to reduce permissions later (Principle of Least Privilege).
* **Programmatic Access Configured Securely:** Access keys for the IAM user were generated and stored locally (`~/.aws/credentials`), strictly avoiding hardcoding them.
* **IAM User MFA Enabled:** Multi-Factor Authentication was enabled for console access for the new IAM user.
* **Git Version Control Initialized:** A local Git repository was set up and connected to a new, empty remote GitHub repository, with an initial commit pushed.
* **Documentation Started:** This `README.md` was created and updated to log all the foundational setup steps and the secure practices implemented.

## Today's Summary (Day 2: AWS S3 for Centralized Log Storage)

Today, the foundation for scalable and durable log storage was established using AWS S3.

* **S3 Concepts Explored:** Gained a thorough understanding of S3 buckets, objects, keys, AWS Regions, and the exceptional "11 nines" data durability.
* **Storage Classes Understood:** Investigated S3 Standard, S3 Intelligent-Tiering (highlighting its cost-saving benefits for unpredictable log data), and S3 Standard-IA, demonstrating an understanding of economic viability in cloud security.
* **Secure S3 Buckets Created:**
    * Two S3 buckets were created in the Virginia region:
        * campbellbaxley-security-raw-logs for raw, untransformed logs.
        * campbellbaxley-security-processed-data for transformed data or analytics results.
    * **Crucially, "Block all public access" was enabled for both buckets**, enforcing a strict security posture.
    * Bucket Versioning and Server-Side Encryption (SSE-S3) were enabled for enhanced data protection.
* **Manual Operations Tested:** Successfully uploaded and downloaded small dummy files to the raw-logs bucket via the AWS Management Console to verify access.

## Day 3: Python Boto3 for S3 Interaction & Credential Management

Today, the project shifted from manual console operations to programmatic interaction with AWS S3 using Python and the Boto3 library, focusing on secure credential handling.

### Environment Setup
-   **Python 3.8+** ensured to be installed.
-   A **virtual environment** (`python -m venv .venv`) was created and activated within the project directory to manage dependencies:
    -   `python -m venv .venv` (to create)
    -   `source .venv/bin/activate` (macOS/Linux) or `.venv\Scripts\activate` (Windows) (to activate)
-   The **Boto3 library** for AWS SDK in Python was installed using pip (`pip install boto3`) within the active virtual environment.

### Secure AWS Credential Configuration
-   **Critical Step:** AWS credentials (Access Key ID and Secret Access Key for the `Campbell IAM` user) were verified to be **securely configured locally** in `~/.aws/credentials` (or as environment variables). This setup is paramount for Boto3 to authenticate with AWS services **without hardcoding sensitive information into the script**, preventing a common and critical security vulnerability.

### S3 Interaction Script (`s3_utils.py`)
-   A Python script, `s3_utils.py`, was developed to encapsulate programmatic S3 operations using Boto3.
-   **Key Functions Implemented:**
    -   `list_s3_buckets()`: Lists all accessible S3 buckets.
        ```python
        # Example Docstring for list_s3_buckets
        def list_s3_buckets():
            """
            Lists all S3 buckets accessible by the configured AWS credentials.
            Returns:
                list: A list of bucket names if successful, None otherwise.
            """
            # ... (function implementation)
        ```
    -   `upload_file_to_s3(file_path, bucket_name, object_name)`: Uploads a local file to a specified S3 bucket.
        ```python
        # Example Docstring for upload_file_to_s3
        def upload_file_to_s3(file_path, bucket_name, object_name=None):
            """
            Uploads a file to an S3 bucket.

            Args:
                file_path (str): Path to the local file to upload.
                bucket_name (str): Name of the S3 bucket.
                object_name (str, optional): S3 object name. If not specified, file_path basename is used.

            Returns:
                bool: True if upload is successful, False otherwise.
            """
            # ... (function implementation)
        ```
    -   `download_file_from_s3(bucket_name, object_name, download_path)`: Downloads a file from an S3 bucket to a local path.
        ```python
        # Example Docstring for download_file_from_s3
        def download_file_from_s3(bucket_name, object_name, download_path):
            """
            Downloads a file from an S3 bucket to a local path.

            Args:
                bucket_name (str): Name of the S3 bucket.
                object_name (str): S3 object name to download.
                download_path (str): Local path where the file will be saved.

            Returns:
                bool: True if download is successful, False otherwise.
            """
            # ... (function implementation)
        ```
-   The `s3_utils.py` script was thoroughly **tested** by listing existing buckets, uploading a dummy file to the campbellbaxley-security-raw-logs bucket, and then successfully downloading it back.

## Day 4: API Activity Monitoring (AWS CloudTrail)

Today, a critical component for security auditing and incident response was implemented: AWS CloudTrail.

* **CloudTrail Understanding:** Gained a deep understanding of CloudTrail's role as an activity recorder, differentiating between **Management Events** (control plane actions like resource creation/modification) and **Data Events** (data plane actions like S3 object access).
* **Dedicated Trail Creation:** A new CloudTrail trail named campbellbaxley-security-trail was created, configured to apply to all regions in the AWS account.
* **S3 Log Delivery:** The trail was configured to deliver logs to the campbellbaxley-security-raw-logs S3 bucket, ensuring long-term, centralized storage of audit logs.
* **Comprehensive Event Logging Enabled:**
    * **Management events (Read/Write)** are enabled to capture all control plane activities.
    * **S3 Data Events are explicitly enabled for the campbellbaxley-security-raw-logs bucket (both Read and Write operations)**. This is a critical security feature, providing granular visibility into data access patterns, vital for detecting data exfiltration and conducting forensic investigations.
* **Log File Integrity Validation Enabled:** This crucial security feature was enabled to prevent attackers from tampering with audit logs, thereby ensuring the reliability and trustworthiness of forensic evidence.
* **CloudWatch Logs Integration (Optional but recommended):** The trail was configured to send logs to a new CloudWatch Logs group campbellbaxley-cloudtrail-logs for real-time monitoring and easier log analysis.
* **Log Delivery Verification:** Confirmed CloudTrail log delivery by performing dummy actions in the AWS account (e.g., creating/deleting an S3 bucket, uploading/downloading files to campbellbaxley-security-raw-logs) and then verifying the presence of corresponding `.json.gz` log files in the designated S3 bucket and CloudWatch Logs.

## Day 5: Network Traffic Visibility (AWS VPC Flow Logs)

Today, network-level visibility was established by configuring AWS VPC Flow Logs to capture IP traffic information within the Virtual Private Cloud (VPC).

* **VPC Flow Logs Understanding:** Gained a deep understanding of VPC Flow Logs' role in capturing IP traffic data (source/destination IPs, ports, protocols, bytes, action) within the VPC. Recognized its utility for network troubleshooting and, critically, for identifying network-based attacks like port scans or unauthorized connections that might otherwise go undetected.
* **S3 Bucket Policy Update:** The campbellbaxley-security-raw-logs S3 bucket policy was updated to explicitly grant `delivery.logs.amazonaws.com` (the VPC Flow Logs service principal) the necessary permissions (`s3:PutObject`) to write flow log files into a dedicated `VPCFlowLogs/` prefix within the bucket.
* **IAM Role for CloudWatch Logs:** A dedicated IAM role (campbellbaxley-VPCFlowLogs-CloudWatchLogs-Role) was meticulously created, granting VPC Flow Logs permissions to publish logs to Amazon CloudWatch Logs. This involved:
    * Creating the role using a generic service (e.g., EC2) as a placeholder.
    * **Manually editing its trust policy** to explicitly allow `vpc-flow-logs.amazonaws.com` to assume the role.
    * Attaching an **inline policy** with granular permissions (`logs:CreateLogGroup`, `logs:CreateLogStream`, `logs:PutLogEvents`, `logs:DescribeLogGroups`, `logs:DescribeLogStreams`) scoped to the campbellbaxley-vpc-flow-logs CloudWatch Logs group.
* **Dual Flow Log Configuration:**
    * **Default VPC Identified:** The primary Default VPC was identified as the target for flow log capture.
    * **Flow Log 1 (to CloudWatch Logs):** A flow log named `yourname-default-vpc-flow-log-to-cloudwatch` was configured for the Default VPC, capturing **All traffic** and sending logs to a new CloudWatch Logs group (`yourname-vpc-flow-logs`, e.g., `campbellbaxley-vpc-flow-logs`), using the dedicated IAM role. This enables real-time analysis and alerting.
    * **Flow Log 2 (to S3 Bucket):** A second flow log named `yourname-default-vpc-flow-log-to-s3` was configured for the *same* Default VPC, also capturing **All traffic** and sending logs to the `yourname-security-raw-logs` S3 bucket. This ensures long-term, cost-effective storage for forensic and compliance purposes.
* **Log Delivery Verification:** Confirmed VPC Flow Log delivery by checking for new log entries in the `yourname-vpc-flow-logs` CloudWatch Log group and verifying the presence of gzipped log files in the `yourname-security-raw-logs` S3 bucket.

## Day 6: Ingesting CloudTrail & VPC Flow Logs into CloudWatch Logs

The goal for this day is to consolidate CloudTrail and VPC Flow Logs into CloudWatch Logs for unified monitoring and analysis. This involves understanding CloudWatch Logs architecture, including log groups and log streams, and performing basic CloudWatch Logs Insights queries. The platforms and services used are the AWS Management Console, AWS CloudWatch Logs, AWS CloudTrail, and AWS VPC Flow Logs.

A review of CloudWatch Logs is essential, understanding its function as a service for monitoring, storing, and accessing log files from various AWS services. This consolidation into a single platform is crucial for achieving a holistic security view, preventing siloed analysis, and accelerating incident investigation. An attacker might perform an API call (logged by CloudTrail) and subsequently initiate network activity (logged by VPC Flow Logs); CloudWatch Logs serves as the central repository, enabling correlation and cross-log analysis through CloudWatch Logs Insights.

The integration of CloudTrail logs into CloudWatch Logs, configured on Day 4, was verified. Similarly, the configuration of VPC Flow Logs to send data to a CloudWatch Logs group, established on Day 5, was confirmed. If any integrations were not active, the respective service configurations were modified to enable log delivery to CloudWatch Logs.

To familiarize oneself with the log structure and query language, basic queries were executed in the CloudWatch Logs Insights console (e.g., `fields @timestamp, @message | limit 20`). Key fields for both log types were identified: `userIdentity`, `eventSource`, `eventName`, `sourceIPAddress` for CloudTrail, and `srcAddr`, `dstAddr`, `action`, `dstPort` for VPC Flow Logs. This process lays the groundwork for creating automated metric filters and alarms in subsequent steps, demonstrating an understanding of the foundational nature of centralized logging for automated security operations.

This day's work centralizes security log data from AWS CloudTrail and VPC Flow Logs into Amazon CloudWatch Logs, enabling unified monitoring and initial log analysis using CloudWatch Logs Insights.

## Day 7: Creating CloudWatch Metric Filters for Suspicious Activities

The objective for this day was to define specific patterns within security logs to identify and count suspicious activities using CloudWatch Metric Filters. This involved acquiring skills in CloudWatch Metric Filter syntax, recognizing critical log patterns ("Access Denied," "Rejected" connections), and associating metrics with these filters. The platforms and services used were the AWS Management Console and AWS CloudWatch Logs.

The process began by understanding how CloudWatch Metric Filters convert raw log data into numerical metrics that can be graphed and used to trigger alarms. This transformation from unstructured log data to quantifiable metrics is crucial for establishing baselines, identifying anomalies, and enabling performance-based alerting.

A metric filter was created for "Access Denied" errors from CloudTrail logs. This involved navigating to the `campbellbaxley-cloudtrail-logs` CloudWatch Logs group and defining a filter pattern to detect "Access Denied" errors: `{ ($.errorCode = "AccessDenied") || ($.errorMessage = "*Access Denied*") }`. A descriptive `Filter Name` (`AccessDeniedErrors`), `Metric Namespace` (`SecurityMetrics`), and `Metric Name` (`CloudTrailAccessDeniedCount`) were assigned, with `Metric Value` set to 1. This approach directly translates threat intelligence into actionable detection rules, as "Access Denied" errors are common indicators of compromise.

Similarly, a metric filter was created for "Rejected Connections" from VPC Flow Logs. This involved navigating to the `campbellbaxley-vpc-flow-logs` CloudWatch Logs group and defining a filter pattern to detect rejected network connections: `{ $.action = "REJECT" }`. A `Filter Name` (`RejectedNetworkTraffic`), `Metric Namespace` (`SecurityMetrics`), and `Metric Name` (`VPCFlowRejectedCount`) were assigned, with `Metric Value` set to 1. Rejected connections can signify port scans or blocked exfiltration attempts, making this a vital detection point.

To validate the filters, actions expected to trigger them (e.g., attempting to access a non-existent S3 bucket for Access Denied; attempting blocked network connections from an EC2 instance for Rejected Connections) were performed, and the corresponding metrics observed in the CloudWatch Metrics console.

This day's work demonstrates the development and implementation of CloudWatch Metric Filters to extract key security indicators from log data, including 'Access Denied' errors from CloudTrail and 'Rejected' network connections from VPC Flow Logs, thereby establishing a baseline for automated threat detection.
