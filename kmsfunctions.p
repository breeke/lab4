import boto3
import json
import os
from botocore.exceptions import ClientError

def upload_encrypted_file_to_s3(local_file_path, s3_key, bucket_name, kms_key_alias):
    """Upload a file to S3 with KMS encryption"""
    try:
        s3 = boto3.client('s3')

        print(f"🔒 Uploading {local_file_path} to s3://{bucket_name}/{s3_key} with KMS encryption...")

        # Upload with server-side encryption using KMS
        s3.upload_file(
            local_file_path,
            bucket_name,
            s3_key,
            ExtraArgs={
                'ServerSideEncryption': 'aws:kms',
                'SSEKMSKeyId': kms_key_alias
            }
        )

        print(f"✅ Successfully uploaded encrypted file: {s3_key}")
        return True

    except ClientError as e:
        print(f"❌ Failed to upload encrypted file: {e}")
        return False

def upload_file_to_s3(local_file_path, s3_key, bucket_name):
    """Upload a file to S3 without encryption"""
    try:
        s3 = boto3.client('s3')

        print(f"📤 Uploading {local_file_path} to s3://{bucket_name}/{s3_key}...")

        # Upload without encryption
        s3.upload_file(local_file_path, bucket_name, s3_key)

        print(f"✅ Successfully uploaded file: {s3_key}")
        return True

    except ClientError as e:
        print(f"❌ Failed to upload file: {e}")
        return False
def download_and_decrypt_file_from_s3(s3_key, local_file_path, bucket_name):
    """Download and automatically decrypt a file from S3"""
    try:
        s3 = boto3.client('s3')

        print(f"🔓 Downloading and decrypting s3://{bucket_name}/{s3_key} to {local_file_path}...")

        # Download file (S3 automatically decrypts if you have KMS permissions)
        s3.download_file(bucket_name, s3_key, local_file_path)

        print(f"✅ Successfully downloaded and decrypted: {local_file_path}")
        return True

    except ClientError as e:
        print(f"❌ Failed to download/decrypt file: {e}")
        return False

def get_object_encryption_info(s3_key, bucket_name):
    """Get encryption information about an S3 object"""
    try:
        s3 = boto3.client('s3')

        response = s3.head_object(Bucket=bucket_name, Key=s3_key)

        encryption_info = {
            'ServerSideEncryption': response.get('ServerSideEncryption', 'None'),
            'SSEKMSKeyId': response.get('SSEKMSKeyId', 'None'),
            'ContentLength': response.get('ContentLength', 0)
        }

        print(f"🔍 Encryption info for {s3_key}:")
        print(f"   Encryption: {encryption_info['ServerSideEncryption']}")
        print(f"   KMS Key: {encryption_info['SSEKMSKeyId']}")
        print(f"   File Size: {encryption_info['ContentLength']} bytes")

        return encryption_info

    except ClientError as e:
        print(f"❌ Error getting object info: {e}")
        return None

def create_test_files():
    """Create some test files to encrypt"""
    test_files = [
        {
            'filename': 'student-info.txt',
            'content': f'''Student Information
===================
Student Number: 23477648
Course: Cloud Computing Lab
Date: {__import__('datetime').datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

This file contains sensitive student information that should be encrypted.
'''
        },
        {
            'filename': 'lab-notes.txt',
            'content': f'''Lab Notes - KMS Encryption
==========================
Student: 23477648

Today I learned about:
1. Creating KMS keys with custom policies
2. Using KMS keys to encrypt S3 objects
3. Setting up key aliases for easy reference
4. Testing encryption and decryption

The KMS key alias/23477648 is working properly!
'''
        },
        {
            'filename': 'sensitive-data.json',
            'content': json.dumps({
                "student_id": "23477648",
                "email": "23477648@student.uwa.edu.au",
                "lab_progress": {
                    "s3_bucket_policy": "completed",
                    "kms_key_creation": "completed",
                    "encryption_testing": "in_progress"
                },
                "secret_note": "This JSON file should be encrypted at rest in S3"
            }, indent=2)
        }
    ]

    print("📝 Creating test files...")
    for file_info in test_files:
        with open(file_info['filename'], 'w') as f:
            f.write(file_info['content'])
        print(f"   ✅ Created: {file_info['filename']}")

    return [f['filename'] for f in test_files]

def test_kms_encryption_workflow(bucket_name="23477648-cloudstorage", kms_alias="alias/23477648"):
    """Complete workflow to test KMS encryption with S3"""

    print("S3 + KMS Encryption Testing Workflow")
    print("=" * 50)
    print(f"Bucket: {bucket_name}")
    print(f"KMS Key Alias: {kms_alias}")
    print(f"Test Folder: rootdir/")

    # Step 1: Create test files
    test_files = create_test_files()

    # Step 2: Upload original files (unencrypted) to S3
    print(f"\n📤 Uploading original files (unencrypted)...")
    original_uploaded_files = []

    for filename in test_files:
        s3_key = f"rootdir/original_{filename}"
        if upload_file_to_s3(filename, s3_key, bucket_name):
            original_uploaded_files.append(s3_key)

    # Step 3: Upload files with KMS encryption
    print(f"\n📤 Uploading files with KMS encryption...")
    encrypted_uploaded_files = []

    for filename in test_files:
        s3_key = f"rootdir/encrypted_{filename}"
        if upload_encrypted_file_to_s3(filename, s3_key, bucket_name, kms_alias):
            encrypted_uploaded_files.append((s3_key, filename))  # Store both s3_key and original filename

    # Step 4: Check encryption status of all uploaded files
    print(f"\n🔍 Checking encryption status...")

    print("Original files (should show no encryption):")
    for s3_key in original_uploaded_files:
        get_object_encryption_info(s3_key, bucket_name)
        print()

    print("Encrypted files (should show KMS encryption):")
    for s3_key, original_filename in encrypted_uploaded_files:
        get_object_encryption_info(s3_key, bucket_name)
        print()

    # Step 5: Download and decrypt files to the same folder
    print(f"📥 Downloading and decrypting files to root directory...")
    decrypted_files = []

    for s3_key, original_filename in encrypted_uploaded_files:
        # Create decrypted filename in the same directory (root)
        base_name = os.path.splitext(original_filename)[0]  # Remove extension
        extension = os.path.splitext(original_filename)[1]  # Get extension
        download_filename = f"{base_name}_decrypted{extension}"

        if download_and_decrypt_file_from_s3(s3_key, download_filename, bucket_name):
            decrypted_files.append(download_filename)
            # Verify file content
            if os.path.exists(download_filename):
                with open(download_filename, 'r') as f:
                    content_preview = f.read()[:100]
                print(f"   📄 Preview: {content_preview}...")

    # Step 6: Upload the decrypted files back to S3 (optional)
    print(f"\n📤 Uploading decrypted files back to S3...")
    decrypted_uploaded_files = []

    for filename in decrypted_files:
        s3_key = f"rootdir/{filename}"
        if upload_file_to_s3(filename, s3_key, bucket_name):
            decrypted_uploaded_files.append(s3_key)

    # Step 7: Create local encrypted versions for demonstration
    print(f"\n🔒 Creating local encrypted versions using direct KMS...")
    local_encrypted_files = []

    try:
        kms = boto3.client('kms')

        for original_filename in test_files:
            # Read original file
            with open(original_filename, 'r') as f:
                original_content = f.read()

            # Encrypt content using KMS
            encrypt_response = kms.encrypt(
                KeyId=kms_alias,
                Plaintext=original_content
            )

            # Save encrypted content to local file
            base_name = os.path.splitext(original_filename)[0]
            extension = os.path.splitext(original_filename)[1]
            encrypted_filename = f"{base_name}_encrypted.bin"

            with open(encrypted_filename, 'wb') as f:
                f.write(encrypt_response['CiphertextBlob'])

            local_encrypted_files.append(encrypted_filename)
            print(f"   ✅ Created local encrypted file: {encrypted_filename}")

    except Exception as e:
        print(f"❌ Error creating local encrypted files: {e}")

    # Step 8: List all files in current directory
    print(f"\n📋 Files created in root directory:")
    all_local_files = []

    # Original files
    for filename in test_files:
        if os.path.exists(filename):
            all_local_files.append(f"📄 {filename} (original)")

    # Local encrypted files
    for filename in local_encrypted_files:
        if os.path.exists(filename):
            all_local_files.append(f"🔒 {filename} (encrypted binary)")

    # Decrypted files
    for filename in decrypted_files:
        if os.path.exists(filename):
            all_local_files.append(f"🔓 {filename} (decrypted from S3)")

    for file_info in all_local_files:
        print(f"   {file_info}")

    # Step 9: List all files in S3 bucket
    print(f"\n📋 All files in S3 bucket rootdir/ with encryption status:")
    try:
        s3 = boto3.client('s3')
        response = s3.list_objects_v2(Bucket=bucket_name, Prefix='rootdir/')

        if 'Contents' in response:
            print("Files in S3:")
            for obj in response['Contents']:
                file_type = ""
                if "original_" in obj['Key']:
                    file_type = "(Original - Unencrypted)"
                elif "encrypted_" in obj['Key']:
                    file_type = "(KMS Encrypted)"
                elif "_decrypted" in obj['Key']:
                    file_type = "(Decrypted copy)"

                print(f"📁 {obj['Key']} {file_type}")
                get_object_encryption_info(obj['Key'], bucket_name)
                print()
    except Exception as e:
        print(f"❌ Error listing bucket contents: {e}")

    # Optional cleanup
    cleanup = input(f"\n🧹 Clean up local test files? (y/n): ").strip().lower()
    if cleanup == 'y':
        print(f"Cleaning up local files...")
        all_cleanup_files = test_files + local_encrypted_files + decrypted_files

        for filename in all_cleanup_files:
            if os.path.exists(filename):
                os.remove(filename)
                print(f"   🗑️ Deleted: {filename}")
    else:
        print(f"📁 All files kept in root directory for your review")

def test_direct_kms_operations(kms_alias="alias/23477648"):
    """Test direct KMS encrypt/decrypt operations"""
    try:
        kms = boto3.client('kms')

        print(f"\n🔐 Testing direct KMS operations with {kms_alias}...")

        # Test data
        test_message = f"Secret message from student 23477648! Timestamp: {__import__('datetime').datetime.now()}"

        print(f"Original message: {test_message}")

        # Encrypt
        print(f"\n🔒 Encrypting with KMS key...")
        encrypt_response = kms.encrypt(
            KeyId=kms_alias,
            Plaintext=test_message
        )

        ciphertext = encrypt_response['CiphertextBlob']
        key_id_used = encrypt_response['KeyId']

        print(f"✅ Encryption successful!")
        print(f"   Key used: {key_id_used}")
        print(f"   Ciphertext size: {len(ciphertext)} bytes")

        # Decrypt
        print(f"\n🔓 Decrypting...")
        decrypt_response = kms.decrypt(CiphertextBlob=ciphertext)

        decrypted_message = decrypt_response['Plaintext'].decode('utf-8')
        key_id_used = decrypt_response['KeyId']

        print(f"✅ Decryption successful!")
        print(f"   Key used: {key_id_used}")
        print(f"   Decrypted message: {decrypted_message}")

        # Verify
        if decrypted_message == test_message:
            print(f"🎉 SUCCESS: Original and decrypted messages match!")
        else:
            print(f"❌ ERROR: Messages don't match!")

    except ClientError as e:
        print(f"❌ KMS operation failed: {e}")
    except Exception as e:
        print(f"❌ Unexpected error: {e}")

def main():
    student_number = "23477648"
    bucket_name = "23477648-cloudstorage"
    kms_alias = f"alias/{student_number}"

    print("KMS Key Creator and S3 Encryption Tester")
    print("=" * 50)
    print(f"Student Number: {student_number}")
    print(f"Bucket: {bucket_name}")
    print(f"KMS Alias: {kms_alias}")

    # Check current identity
    try:
        sts = boto3.client('sts')
        identity = sts.get_caller_identity()
        print(f"👤 Current user: {identity['Arn']}")
    except:
        print("⚠️ Could not get current user identity")

    # Check if KMS key already exists
    try:
        kms = boto3.client('kms')
        kms.describe_key(KeyId=kms_alias)
        print(f"\n✅ KMS key with alias {kms_alias} already exists!")

        # Test direct KMS operations
        test_direct_kms_operations(kms_alias)

        # Test S3 encryption workflow
        test_s3 = input(f"\nTest S3 encryption workflow with existing key? (y/n): ").strip().lower()
        if test_s3 == 'y':
            test_kms_encryption_workflow(bucket_name, kms_alias)

    except ClientError as e:
        if e.response['Error']['Code'] == 'NotFoundException':
            print(f"\n⚠️ KMS key with alias {kms_alias} not found!")

            create_new = input("Create new KMS key? (y/n): ").strip().lower()
            if create_new == 'y':
                key_id, alias_name = create_kms_key_with_alias(student_number)

                if key_id and alias_name:
                    print(f"\n🎉 KMS Key Setup Complete!")

                    # Test the new key
                    test_direct_kms_operations(alias_name)

                    # Test S3 encryption
                    test_s3 = input(f"\nTest S3 encryption workflow? (y/n): ").strip().lower()
                    if test_s3 == 'y':
                        test_kms_encryption_workflow(bucket_name, alias_name)
        else:
            print(f"❌ Error checking KMS key: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nScript interrupted by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
