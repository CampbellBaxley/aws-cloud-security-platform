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
