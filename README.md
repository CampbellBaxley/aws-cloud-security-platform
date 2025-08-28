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

## Day 8: Setting Up CloudWatch Alarms for Security Events

The goal for this day was to create CloudWatch Alarms that trigger notifications when the metrics from the previously defined filters exceed predefined thresholds. This required understanding CloudWatch Alarms configuration, including alarm states (OK, ALARM, INSUFFICIENT_DATA), threshold setting, and notification actions. The platforms and services involved are the AWS Management Console, AWS CloudWatch Alarms, and AWS SNS (as the notification target).

A thorough understanding of CloudWatch Alarms, their various states, and their function in monitoring metrics to trigger actions was established. The transition from merely logging events to setting alarms represents a fundamental shift from reactive security (investigating after an event) to proactive security (being alerted *as* an event unfolds), significantly reducing the Mean Time To Detect (MTTD).

First, an Amazon SNS (Simple Notification Service) topic campbellbaxley-security-alerts was created to serve as the notification channel. The user's email address was subscribed to this SNS topic, and the subscription was successfully confirmed via the email received.

Next, a CloudWatch Alarm was created for the `CloudTrailAccessDeniedCount` metric (from the `SecurityMetrics` namespace). The alarm (`HighAccessDeniedAlarm`) was configured with a `Statistic` of `Sum` over a `Period` of 5 minutes. A `Static Threshold` type was set, with the alarm triggering `Whenever CloudTrailAccessDeniedCount is Greater than 3`. This means that if three or more "Access Denied" errors occur within a five-minute window, the alarm will trigger. The `campbellbaxley-security-alerts` SNS topic was selected for notification.

A similar alarm was created for the `VPCFlowRejectedCount` metric. This alarm (`HighRejectedTrafficAlarm`) was configured with a `Statistic` of `Sum` over a `Period` of 5 minutes. The threshold was set to `Greater than 5 rejected connections` in 5 minutes, linking it to the same `campbellbaxley-security-alerts` SNS topic. This demonstrates the practical challenge of tuning detection rules to balance detecting genuine threats and preventing alert fatigue.

To test the alarms, actions expected to generate "Access Denied" errors (e.g., repeatedly attempting to create a non-existent S3 bucket) and rejected network connections (e.g., attempting a blocked outbound connection from an EC2 instance) were intentionally performed multiple times within the specified period. The successful receipt of email notifications from both alarms was verified.

This day's work demonstrates the configuration of Amazon CloudWatch Alarms to proactively monitor security metrics, triggering real-time notifications via Amazon SNS for critical events such as excessive 'Access Denied' attempts and suspicious network traffic.


## Day 9: Configuring Amazon SNS for Security Alerts

The goal for this day was to deepen the understanding of Amazon SNS and ensure its comprehensive configuration for various security alert types. This involved reinforcing skills in SNS topic management, understanding different subscription types (with a focus on email), and conceptually grasping message publishing. The platforms and services primarily used are the AWS Management Console and AWS SNS.

A review of SNS fundamentals was crucial, focusing on its role as a "fan-out" service for notifications. This design principle, where SNS acts as a decoupling layer between detection mechanisms (like CloudWatch Alarms and future GuardDuty integrations) and notification consumers (such as email or Lambda functions), is critical for scalable and resilient alerting.

The confirmation status of the email subscription to the `campbellbaxley-security-alerts` SNS topic was double-checked and verified to be `Confirmed`. A test message was then manually published to the `campbellbaxley-security-alerts` SNS topic via the AWS Console to confirm the end-to-end notification path to the subscribed email address.

While full implementation was not required, the Boto3 documentation for publishing messages to an SNS topic was reviewed to understand how automated systems (e.g., Lambda functions) would programmatically send alerts. This understanding of SNS's broader capabilities, beyond simple email, hints at future, more sophisticated integrations with incident response tools or ticketing systems.


## Day 10: Integrating Amazon GuardDuty for Intelligent Threat Detection

The objective for this day was to enable and integrate Amazon GuardDuty, a managed threat detection service, to enhance security monitoring. This involved learning about GuardDuty enablement, understanding its finding types and severity, generating sample findings, and integrating with EventBridge for alerts. The platforms and services utilized include the AWS Management Console, AWS GuardDuty, AWS EventBridge, and AWS SNS.

A thorough understanding of GuardDuty's capabilities was paramount. It is an intelligent threat detection service that analyzes CloudTrail, VPC Flow Logs, and DNS logs using machine learning and threat intelligence. This represents a strategic shift from building custom detection logic to leveraging AWS's managed security intelligence, offloading the burden of maintaining threat intelligence and ML models. Understanding its finding types and severity levels (Low, Medium, High) is also important.

GuardDuty was enabled in the AWS Management Console, noting its 30-day free trial. To facilitate testing of the alerting setup without performing actual malicious activities, sample findings were generated directly from the GuardDuty console. The ability to generate sample findings is a critical component of security testing and validation, allowing for safe and repeatable security operations.

An EventBridge rule was then configured to route GuardDuty findings to the SNS topic. In the AWS EventBridge console, a new rule (`campbellbaxley-guardduty-findings-to-sns`) was created. The `Event source` was set to `AWS services`, and the `AWS service` was set to `GuardDuty` with the `Event type` of `GuardDuty Finding`. The `Target` was selected as an `SNS topic`, pointing to the `campbellbaxley-security-alerts` SNS topic.

To test the integration, new sample GuardDuty findings were generated, and the receipt of email notifications via SNS was verified. This day's work demonstrates the integration of Amazon GuardDuty for intelligent, continuous threat detection across AWS accounts and workloads, leveraging machine learning and threat intelligence to identify suspicious activities and funnel findings to a centralized alerting system.

## Day 11: Introduction to AWS Lambda & Basic Function Creation

The goal for this day was to understand AWS Lambda fundamentals and create a first Python Lambda function. This involved acquiring skills in serverless computing concepts, Lambda function creation, execution roles, event-driven architecture, and basic Python for Lambda. The platforms and services utilized were the AWS Management Console, AWS Lambda, and AWS IAM.

The process began by researching Lambda as a serverless compute service that executes code in response to events. Key aspects to understand are its pay-per-use model and automatic scaling capabilities. Lambda's serverless nature means that remediation functions only run when needed and scale automatically, making them highly cost-effective and performant for incident response. This demonstrates an understanding of optimizing cloud resources for security operations.

A basic Lambda function named `campbellbaxley-security-remediation-processor` was created in the AWS Lambda console. Python 3.x was chosen as the runtime. For the `Execution role`, a new role with basic Lambda permissions was created, which automatically grants the function permission to upload logs to CloudWatch Logs. Understanding that Lambda functions operate under an IAM execution role is crucial for security, as it reinforces the principle of least privilege in the context of automated actions. A simple Python "Hello World" code was pasted into the function editor.

The function was then tested using the "Test" button in the Lambda console, verifying successful execution and log output to CloudWatch Logs. This day's work demonstrates the acquisition of foundational knowledge in serverless computing by developing and deploying an AWS Lambda function, thereby showcasing proficiency in event-driven architecture and basic cloud automation.

## Day 12: Lambda for Automated IAM Remediation (e.g., Revoking Access Keys)

The goal for this day was to create a Lambda function that automatically revokes an exposed IAM user access key, triggered by a security finding. This involved acquiring skills in Python Boto3 for IAM, parsing JSON event data, and understanding IAM policy management. The platforms and services utilized are AWS Lambda, AWS IAM, AWS EventBridge, and AWS SNS.

The remediation scenario focused on "Exposed Access Keys," a common security risk. Automated remediation in this context dramatically reduces the time an attacker has to exploit a compromised credential, directly impacting the "Containment" phase of incident response.

A new Lambda function (`campbellbaxley-revoke-access-key-lambda`) was created. Its execution role was modified to include IAM permissions necessary to list and deactivate access keys for IAM users (`iam:ListAccessKeys`, `iam:UpdateAccessKey`). It is paramount to adhere to the principle of least privilege by limiting these permissions. The explicit instruction to grant only the necessary IAM permissions to the Lambda execution role reinforces this principle for automated actions, preventing over-privileged functions that could be exploited.

The Python code for the Lambda function, using Boto3, was written to:
- Parse a test JSON event to extract the `AccessKeyId` and `UserName`.
- Use `iam.client.update_access_key()` to set the key's status to `Inactive`.
- Send a notification via SNS to confirm the action taken.

To test the remediation, a dummy IAM user with an access key was created. A manual test event, mimicking an exposed access key for this dummy user, was sent to the Lambda function. The successful deactivation of the access key by the Lambda function and the receipt of an SNS notification were verified.

This day's work demonstrates the development and deployment of an automated, event-driven AWS Lambda function for IAM remediation, capable of deactivating exposed access keys in response to security findings, thereby significantly reducing the window of vulnerability.

## Day 13: Lambda for Automated Network Remediation (e.g., Blocking Malicious IPs via NACLs)

The objective for this day was to create a Lambda function that automatically blocks malicious IP addresses at the network level using Network Access Control Lists (NACLs). This involved acquiring skills in Python Boto3 for EC2/VPC (NACLs), understanding network security concepts (NACLs vs. Security Groups), and IP address parsing.

The platforms and services utilized are AWS Lambda, AWS EC2 (VPC, NACLs), AWS EventBridge, and AWS S3 (for a blocked IP list). A foundational understanding of NACLs as stateless firewalls at the subnet level, and their distinction from stateful Security Groups, was established. Implementing both demonstrates an understanding of layered network security.

A new S3 bucket (`campbellbaxley-blocked-ips`) was created to store a list of blocked IP addresses, illustrating the concept of operationalizing threat intelligence, where remediation actions feed back into future detection capabilities.

A new Lambda function (`campbellbaxley-block-ip-nacl-lambda`) was created, and its execution role was modified to include permissions to describe and modify NACLs (`ec2:DescribeNetworkAcls`, `ec2:CreateNetworkAclEntry`, etc.) and to add blocked IPs to the S3 bucket (`s3:PutObject`).

The Python code for the Lambda function, using Boto3, was written to:
- Parse an incoming EventBridge event from GuardDuty to extract the malicious sourceIPAddress.
- Use `ec2.client.create_network_acl_entry` to add a `DENY` rule for the malicious IP in the default NACL. A high rule number (e.g., 1000) was used to ensure the rule is processed first.
- Add the blocked IP to a `blocked_ips.txt` file in the `campbellbaxley-blocked-ips` S3 bucket.
- Send an SNS notification confirming the action.

An EventBridge rule was configured to trigger this Lambda function specifically for GuardDuty findings like `UnauthorizedAccess:EC2/SSHBruteForce` and `Portscan:EC2/ExternalPortscan`. The successful blocking of the IP in the NACL, its addition to the S3 list, and the receipt of an SNS notification were all verified by generating a sample GuardDuty finding.

This day's work demonstrates automated network-level incident response by developing an AWS Lambda function to dynamically block malicious IP addresses in Network Access Control Lists (NACLs) based on real-time threat intelligence from Amazon GuardDuty.

## Day 14: Automated EC2 Instance Isolation (Security Groups)

The goal for this day was to create a Lambda function that automatically isolates a compromised EC2 instance by modifying its associated Security Groups. This is a critical capability for containing threats and preventing lateral movement within the network. The platforms and services utilized are AWS Lambda, AWS EC2 (Security Groups), AWS EventBridge, and AWS SNS.

The concept of isolating a compromised EC2 instance is critical to prevent further damage or lateral movement. This directly addresses the "Containment" phase of incident response, where rapid isolation of a compromised resource is paramount.

An "Isolation" Security Group (`campbellbaxley-isolation-sg`) was created in the EC2 console, configured with explicit `DENY ALL` inbound and outbound rules, to act as a quarantine.

A new Lambda function (`campbellbaxley-isolate-ec2-lambda`) was created. Its execution role was modified to include permissions to describe EC2 instances and modify security groups (`ec2:DescribeInstances`, `ec2:ModifyInstanceAttribute`), adhering to the principle of least privilege.

The Python code for the Lambda function, using Boto3, was written to:
- Parse an incoming GuardDuty finding for the `instanceId`.
- Use `ec2.client.modify_instance_attribute()` to detach the instance from its current security group and attach it to the `campbellbaxley-isolation-sg`.
- Send an SNS notification confirming the isolation.

An EventBridge rule was configured to trigger this Lambda function for GuardDuty findings related to EC2 compromise (e.g., `UnauthorizedAccess:EC2/MaliciousIpCaller.DNS`). The successful change of the EC2 instance's security group to the isolation group, effectively cutting off its network access, was verified. This day's work demonstrates the engineering of automated EC2 instance isolation capabilities using AWS Lambda and Security Groups, enabling rapid containment of compromised compute resources in response to detected threats.
