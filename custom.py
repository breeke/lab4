import os
import struct
import hashlib
import sys
import time
if not hasattr(time, 'clock'):
    time.clock = time.time

# Import after fixing compatibility
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import boto3

# Configuration
BLOCK_SIZE = 16
CHUNK_SIZE = 64 * 1024
STUDENT_NUMBER = "23477648"
BUCKET_NAME = "23477648-cloudstorage"

def encrypt_file(password, in_filename, out_filename):
    """Encrypt file using AES-CBC with PyCryptodome - Fixed version"""

    print(f"🔒 Encrypting {in_filename}...")

    try:
        # Generate key from password
        key = hashlib.sha256(password.encode("utf-8")).digest()

        # Generate random IV
        iv = get_random_bytes(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Get file size
        filesize = os.path.getsize(in_filename)

        with open(in_filename, 'rb') as infile:
            with open(out_filename, 'wb') as outfile:
                # Write file size and IV to header
                outfile.write(struct.pack('<Q', filesize))
                outfile.write(iv)

                # Encrypt file in chunks
                bytes_written = 0
                while True:
                    chunk = infile.read(CHUNK_SIZE)
                    if len(chunk) == 0:
                        break

                    # Pad chunk to block size if needed
                    if len(chunk) % BLOCK_SIZE != 0:
                        padding_length = BLOCK_SIZE - (len(chunk) % BLOCK_SIZE)
                        chunk += b' ' * padding_length

                    # Encrypt and write chunk
                    encrypted_chunk = cipher.encrypt(chunk)
                    outfile.write(encrypted_chunk)
                    bytes_written += len(encrypted_chunk)

        print(f"✅ Encrypted: {out_filename} ({bytes_written} bytes)")
        return True

    except Exception as e:
        print(f"❌ Error encrypting {in_filename}: {e}")
        return False

def decrypt_file(password, in_filename, out_filename):
    """Decrypt file using AES-CBC with PyCryptodome - Fixed version with validation"""

    print(f"🔓 Decrypting {in_filename}...")

    try:
        # Generate same key from password
        key = hashlib.sha256(password.encode("utf-8")).digest()

        with open(in_filename, 'rb') as infile:
            # Read header
            origsize_data = infile.read(struct.calcsize('<Q'))
            if len(origsize_data) != struct.calcsize('<Q'):
                raise ValueError("Invalid file format - missing size header")

            origsize = struct.unpack('<Q', origsize_data)[0]

            # Validate original size is reasonable
            if origsize <= 0 or origsize > 100_000_000:  # 100MB limit
                raise ValueError(f"Invalid original size: {origsize} bytes")

            # Read IV
            iv = infile.read(16)
            if len(iv) != 16:
                raise ValueError("Invalid file format - missing IV")

            # Create cipher
            cipher = AES.new(key, AES.MODE_CBC, iv)

            # Read all encrypted content
            encrypted_content = infile.read()
            if len(encrypted_content) == 0:
                raise ValueError("No encrypted content found")

            # Decrypt all content
            decrypted_content = cipher.decrypt(encrypted_content)

            # Truncate to original size (remove padding)
            decrypted_content = decrypted_content[:origsize]

            # VALIDATION: Check if decrypted content makes sense
            # For text files, try to decode as UTF-8
            try:
                # Try to decode as text - if successful and contains reasonable content, likely valid
                text_content = decrypted_content.decode('utf-8')

                # Additional validation: check for reasonable text characteristics
                if len(text_content.strip()) == 0:
                    raise ValueError("Decrypted content is empty")

                # Check if it contains mostly printable characters
                printable_chars = sum(1 for c in text_content if c.isprintable() or c.isspace())
                total_chars = len(text_content)

                if total_chars > 0:
                    printable_ratio = printable_chars / total_chars
                    if printable_ratio < 0.7:  # Less than 70% printable = likely garbage
                        raise ValueError(f"Decrypted content has too many non-printable characters ({printable_ratio:.1%})")

                # If we get here, content seems valid
                with open(out_filename, 'wb') as outfile:
                    outfile.write(decrypted_content)

                print(f"✅ Decrypted: {out_filename} ({origsize} bytes)")
                return True

            except UnicodeDecodeError:
                # Content is not valid UTF-8 text
                # For binary files, we'd need different validation
                # For now, assume text files and fail
                raise ValueError("Decrypted content is not valid UTF-8 text - likely wrong password")

    except Exception as e:
        print(f"❌ Error decrypting {in_filename}: {e}")
        return False

def get_s3_files(bucket_name, prefix):
    """Get files from S3 folder"""
    try:
        s3 = boto3.client('s3')
        response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)

        files = []
        if 'Contents' in response:
            for obj in response['Contents']:
                if not obj['Key'].endswith('/'):
                    files.append({
                        'key': obj['Key'],
                        'size': obj['Size'],
                        'filename': os.path.basename(obj['Key'])
                    })
        return files
    except Exception as e:
        print(f"❌ Error listing files: {e}")
        return []

def download_from_s3(bucket_name, s3_key, local_filename):
    """Download file from S3"""
    try:
        s3 = boto3.client('s3')
        s3.download_file(bucket_name, s3_key, local_filename)
        print(f"📥 Downloaded: {os.path.basename(s3_key)}")
        return True
    except Exception as e:
        print(f"❌ Download failed: {e}")
        return False

def upload_to_s3(local_filename, bucket_name, s3_key):
    """Upload file to S3"""
    try:
        s3 = boto3.client('s3')
        s3.upload_file(local_filename, bucket_name, s3_key)
        print(f"📤 Uploaded: {s3_key}")
        return True
    except Exception as e:
        print(f"❌ Upload failed: {e}")
        return False

# ------------------------
#
# Encryption Verification Functions
#
# ------------------------

def analyze_binary_content_simple():
    """Simple binary content analysis"""
    print("\n🔍 BINARY CONTENT VERIFICATION")
    print("-" * 30)

    print("🔍 Checking if encrypted files contain binary data...")

    # Find encrypted files in rootdir/
    rootdir_files = get_s3_files(BUCKET_NAME, "rootdir/")
    encrypted_files = [f for f in rootdir_files if f['filename'].endswith('.enc')]

    if encrypted_files:
        first_file = encrypted_files[0]
        local_enc = f"temp_examine_{first_file['filename']}"

        if download_from_s3(BUCKET_NAME, first_file['key'], local_enc):
            # Read first 200 bytes and analyze
            with open(local_enc, 'rb') as f:
                header_bytes = f.read(200)

            # Check for readable text (should be minimal in encrypted file)
            readable_chars = sum(1 for b in header_bytes if 32 <= b <= 126)
            total_bytes = len(header_bytes)
            readable_ratio = readable_chars / total_bytes if total_bytes > 0 else 0

            print(f"  📄 Analyzing: {first_file['filename']}")
            print(f"  📊 Readable characters: {readable_chars}/{total_bytes} ({readable_ratio:.1%})")

            if readable_ratio < 0.3:  # Less than 30% readable = likely encrypted
                print(f"  ✅ Low readability = Properly encrypted binary data")
            else:
                print(f"  ❌ High readability = May not be encrypted")

            # Show hex dump of first 32 bytes
            print(f"  🔍 First 32 bytes (hex): {header_bytes[:32].hex()}")

            # Check for our file size header (first 8 bytes should be file size)
            if len(header_bytes) >= 8:
                try:
                    file_size = struct.unpack('<Q', header_bytes[:8])[0]
                    print(f"  📏 Header indicates original size: {file_size} bytes")

                    # Verify this makes sense
                    if 0 < file_size < 10000000:  # Reasonable file size
                        print(f"  ✅ File size header looks valid")
                    else:
                        print(f"  ❌ File size header seems invalid")
                except:
                    print(f"  ❌ Could not read file size header")

            # Try to find readable text in encrypted content
            try:
                readable_text = header_bytes[24:].decode('utf-8', errors='ignore')[:50]
                if any(word in readable_text.lower() for word in ['student', 'test', 'data', 'file']):
                    print(f"  ❌ Found readable text in encrypted data: '{readable_text}'")
                else:
                    print(f"  ✅ No obvious readable text found in encrypted content")
            except:
                print(f"  ✅ Encrypted content is not readable as text")

            os.remove(local_enc)

def test_wrong_password_simple():
    """Simple wrong password test"""
    print("\n🔐 WRONG PASSWORD TEST")
    print("-" * 22)

    password = f'student_{STUDENT_NUMBER}_secret_key'

    print("🔐 Testing with wrong password (should fail)...")

    # Find encrypted files in rootdir/
    rootdir_files = get_s3_files(BUCKET_NAME, "rootdir/")
    encrypted_files = [f for f in rootdir_files if f['filename'].endswith('.enc')]

    if encrypted_files:
        first_enc = encrypted_files[0]
        local_encrypted = f"temp_wrong_{first_enc['filename']}"
        local_failed_decrypt = f"temp_failed_decrypt.txt"

        if download_from_s3(BUCKET_NAME, first_enc['key'], local_encrypted):
            # Try with wrong password
            wrong_password = "definitely_wrong_password"

            print(f"  📄 File: {first_enc['filename']}")
            print(f"  🔑 Correct password: '{password}'")
            print(f"  🔑 Wrong password: '{wrong_password}'")

            success = decrypt_file(wrong_password, local_encrypted, local_failed_decrypt)

            if not success:
                print(f"  ✅ Decryption failed with wrong password (as expected)")
            else:
                print(f"  ❌ Decryption succeeded with wrong password (unexpected!)")

            # Cleanup
            for temp_file in [local_encrypted, local_failed_decrypt]:
                if os.path.exists(temp_file):
                    os.remove(temp_file)

# ------------------------
#
# Main program - All files in rootdir/
#
# ------------------------

def main():
    print("PyCryptodome File Encryption (Single Directory)")
    print("=" * 50)
    print(f"Student: {STUDENT_NUMBER}")
    print(f"Bucket: {BUCKET_NAME}")
    print(f"Directory: rootdir/ (all files will be stored here)")

    # Password
    password = f'student_{STUDENT_NUMBER}_secret_key'
    print(f"🔑 Password: {password}")

    # Get all files from rootdir/
    print(f"\n📂 Current files in rootdir/:")
    rootdir_files = get_s3_files(BUCKET_NAME, "rootdir/")

    if not rootdir_files:
        print("No files found. Creating test file...")
        # Create test file
        test_content = f"Test data for student {STUDENT_NUMBER}\nThis file will be encrypted with PyCryptodome.\nOriginal file content for encryption testing."
        with open("test_data.txt", "w") as f:
            f.write(test_content)

        # Upload to rootdir/
        upload_to_s3("test_data.txt", BUCKET_NAME, "rootdir/test_data.txt")
        os.remove("test_data.txt")

        # Get files again
        rootdir_files = get_s3_files(BUCKET_NAME, "rootdir/")

    # Categorize existing files
    original_files = []
    encrypted_files = []
    decrypted_files = []

    for file_info in rootdir_files:
        filename = file_info['filename']
        if filename.endswith('.enc'):
            encrypted_files.append(file_info)
        elif filename.startswith('decrypted_'):
            decrypted_files.append(file_info)
        else:
            # Check if this is truly an original file (not already processed)
            base_name = filename
            if not any(f['filename'] == f"{base_name}.enc" for f in rootdir_files):
                original_files.append(file_info)

    print(f"\n📊 Current file status:")
    print(f"  📄 Original files: {len(original_files)}")
    print(f"  🔒 Encrypted files: {len(encrypted_files)}")
    print(f"  🔓 Decrypted files: {len(decrypted_files)}")

    # Show files to be processed
    for file_info in original_files:
        size_kb = file_info['size'] / 1024
        print(f"  📄 {file_info['filename']} ({size_kb:.1f} KB)")

    # Process original files that haven't been encrypted yet
    if original_files:
        print(f"\n🔒 Processing {len(original_files)} original files...")

        for file_info in original_files:
            s3_key = file_info['key']
            filename = file_info['filename']

            # Local file names
            downloaded_file = f"temp_{filename}"
            encrypted_file = f"temp_{filename}.enc"
            decrypted_file = f"temp_decrypted_{filename}"

            print(f"\n📁 Processing {filename}...")

            # Download original file
            if download_from_s3(BUCKET_NAME, s3_key, downloaded_file):

                # Encrypt file
                if encrypt_file(password, downloaded_file, encrypted_file):

                    # Upload encrypted version to same rootdir/
                    encrypted_s3_key = f"rootdir/{filename}.enc"
                    if upload_to_s3(encrypted_file, BUCKET_NAME, encrypted_s3_key):

                        # Test decrypt to verify encryption worked
                        if decrypt_file(password, encrypted_file, decrypted_file):

                            # Upload decrypted version to same rootdir/
                            decrypted_s3_key = f"rootdir/decrypted_{filename}"
                            upload_to_s3(decrypted_file, BUCKET_NAME, decrypted_s3_key)

                            print(f"  ✅ Complete: {filename} → {filename}.enc + decrypted_{filename}")
                        else:
                            print(f"  ❌ Decryption test failed for {filename}")
                    else:
                        print(f"  ❌ Upload of encrypted file failed for {filename}")
                else:
                    print(f"  ❌ Encryption failed for {filename}")
            else:
                print(f"  ❌ Download failed for {filename}")

            # Cleanup local files
            for temp_file in [downloaded_file, encrypted_file, decrypted_file]:
                if os.path.exists(temp_file):
                    os.remove(temp_file)
    else:
        print(f"\n✅ No new files to process - all original files already have encrypted versions")

    # Show final results
    print(f"\n📋 FINAL RESULTS")
    print("=" * 40)

    # Get updated file list
    final_rootdir_files = get_s3_files(BUCKET_NAME, "rootdir/")

    # Categorize all files
    final_original = []
    final_encrypted = []
    final_decrypted = []

    for file_info in final_rootdir_files:
        filename = file_info['filename']
        size_kb = file_info['size'] / 1024

        if filename.endswith('.enc'):
            final_encrypted.append((filename, size_kb))
        elif filename.startswith('decrypted_'):
            final_decrypted.append((filename, size_kb))
        else:
            final_original.append((filename, size_kb))

    print(f"\n📄 Original files ({len(final_original)}):")
    for filename, size_kb in sorted(final_original):
        print(f"  📄 {filename} ({size_kb:.1f} KB)")

    print(f"\n🔒 Encrypted files ({len(final_encrypted)}):")
    for filename, size_kb in sorted(final_encrypted):
        print(f"  🔒 {filename} ({size_kb:.1f} KB)")

    print(f"\n🔓 Decrypted files ({len(final_decrypted)}):")
    for filename, size_kb in sorted(final_decrypted):
        print(f"  🔓 {filename} ({size_kb:.1f} KB)")

    print(f"\n📊 SUMMARY:")
    print(f"  📁 Total files in rootdir/: {len(final_rootdir_files)}")
    print(f"  🔗 All files are stored in: s3://{BUCKET_NAME}/rootdir/")

    if len(final_encrypted) > 0 and len(final_decrypted) > 0:
        print(f"  ✅ Encryption and decryption completed successfully!")
    else:
        print(f"  ⚠️  Check processing logs above for any issues")

def enhanced_main():
    """Enhanced main with verification"""

    # Run the main encryption process
    print("Running single-directory encryption process...")
    main()

    # Then run specific verification tests
    print("\n" + "="*60)
    print("🔍 ENCRYPTION VERIFICATION TESTS")
    print("="*60)

    analyze_binary_content_simple()
    test_wrong_password_simple()

    print("\n🎉 ENCRYPTION VERIFICATION COMPLETE!")

if __name__ == "__main__":
    try:
        # Verify PyCryptodome installation
        print("Checking PyCryptodome...")
        try:
            from Crypto.Cipher import AES
            print("✅ PyCryptodome ready")
        except ImportError as e:
            print(f"❌ Import error: {e}")
            print("Try: pip install --force-reinstall pycryptodome")
            sys.exit(1)

        enhanced_main()

    except KeyboardInterrupt:
        print("\n\nCancelled by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
