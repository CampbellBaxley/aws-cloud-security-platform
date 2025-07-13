import boto3
import logging
from botocore.exceptions import ClientError

# Configure logging for better visibility
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Initialize the S3 client
s3_client = boto3.client('s3')

def list_s3_buckets():
    """ Lists all S3 buckets accessible by the configured AWS credentials. """
    logger.info("Attempting to list S3 buckets...")
    try:
        response = s3_client.list_buckets()
        buckets = [bucket['Name'] for bucket in response['Buckets']]
        logger.info("Successfully listed S3 buckets.")
        return buckets
    except ClientError as e:
        logger.erro(f"Failed to list S3 buckets: {e}")
        return None
    
def upload_file_to_s3(file_path, bucket_name, object_name=None):
    """
    Uploads a file to an S3 bucket.

    :param file_path: Path to the local file to upload.
    :param bucket_name: Name of the S3 bucket.
    :param object_name: S3 object name. If not specified, file_path basename is used.
    """
    if object_name is None:
        object_name = file_path.split('/')[-1] # Get the fileename from the path

    logger.info(f"Attempting to upload '{file_path}' to bucket '{bucket_name}'...")
    try:
        s3_client.upload_file(file_path, bucket_name, object_name)
        logger.info(f"Successfully uploaded '{object_name}' to '{bucket_name}'.")
        return True
    except ClientError as e:
        logger.error(f"Failed to upload '{object_name}' to '{bucket_name}': {e}")
        return False
    
def download_file_from_s3(bucket_name, object_name, download_path):
    """
    Downloads a file from an S3 bucket to a local path.
    
    :param bucket_name: Name of the S3 bucket.
    :param object_name: S3 object name to download.
    :param download_path: Local path where the file will be saved.
    """
    logger.info(f"Attempting to download '{object_name}' from bucket '{bucket_name}' to '{download_path}'...")
    try:
        s3_client.download_file(bucket_name, object_name, download_path)
        logger.info(f"Successfully downloaded '{object_name}' to '{download_path}'.")
        return True
    except ClientError as e:
        logger.error(f"Failed to download '{object_name}' from '{bucket_name}': {e}")
        return False
    
if __name__ == "__main__":
    # --- Test Listing Buckets ---
    print("\n--- Listing S3 Buckets ---")
    buckets = list_s3_buckets()
    if buckets:
        print("Available S3 Buckets:")
        for bucket in buckets:
            print(f"- {bucket}")
    else:
        print("No buckets found or error occurred." )
    
    # --- Test Upload and Download ---
    your_raw_logs_bucket = "campbellbaxley-security-raw-logs" 
    dummy_file_name = "programmatic_test_log.txt"
    dummy_file_content = "This is a test log entry uploaded programmatically via Boto3."
    downloaded_file_name = "downloaded_test_log.txt"

    # Create a local dummy file for upload test
    with open(dummy_file_name, 'w') as f:
        f.write(dummy_file_content)
    logger.info(f"Created local dummy file: {dummy_file_name}")

    print(f"\n--- Testing Upload to {your_raw_logs_bucket} ---")
    if upload_file_to_s3(dummy_file_name, your_raw_logs_bucket):
        print(f"Upload of '{dummy_file_name}' successful.")

        print(f"\n--- Testing Download from {your_raw_logs_bucket} ---")
        if download_file_from_s3(your_raw_logs_bucket, dummy_file_name, downloaded_file_name):
            print(f"Download of '{dummy_file_name}' successful to '{downloaded_file_name}'.")
            # Verify content
            with open(downloaded_file_name, 'r') as f:
                content = f.read()
            print(f"Downloaded content: '{content}'")
        else:
            print(f"Download of '{dummy_file_name}' failed.")
    else:
        print(f"Upload of '{dummy_file_name}' failed. Skipping download test.")

    # Clean up local dummy files (optional, but good practice)
    import os
    if os.path.exists(dummy_file_name):
        os.remove(dummy_file_name)
        logger.info(f"Cleaned up local file: {dummy_file_name}")
    if os.path.exists(downloaded_file_name):
        os.remove(downloaded_file_name)
        logger.info(f"Cleaned up local file: {downloaded_file_name}")

    print("\n--- Boto3 S3 Interaction Test Complete ---")