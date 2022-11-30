"""
This is for moving files from local to AWS S3 Bucket.
The design is as described in the Flow Chart for Update 2.0 (subject to change).

Note:
    Empty folders will NOT be uploaded to the bucket!
"""
import os
import traceback
import boto3
import s3fs
import win32security
import json
import logging
from botocore.exceptions import ClientError


s3 = boto3.resource("s3")
s3_client = boto3.client("s3")
s3_file = s3fs.S3FileSystem()
iam = boto3.client('iam')

# AWS_ACCESS_KEY_ID =
# AWS_SECRET_ACCESS_KEY =

# s3_client = boto3.client(
#     service_name="s3",
#     region_name="ca-central-1",
#     aws_access_key_id=AWS_ACCESS_KEY_ID,
#     aws_secret_access_key=AWS_SECRET_ACCESS_KEY
# )

# s3 = boto3.resource(
#     service_name="s3",
#     region_name="ca-central-1",
#     aws_access_key_id=AWS_ACCESS_KEY_ID,
#     aws_secret_access_key=AWS_SECRET_ACCESS_KEY
# )

# s3_file = s3fs.S3FileSystem(key=AWS_ACCESS_KEY_ID,
#                             secret=AWS_SECRET_ACCESS_KEY)


# For demo purposes
bucket_directory_path = ""

CONVENTIONAL_ACES = {
    win32security.ACCESS_ALLOWED_ACE_TYPE: "ALLOW",
    win32security.ACCESS_DENIED_ACE_TYPE: "DENY"
}


def move_local_to_s3(sub_directory_path: str, bucket_name: str):
    """
    Moves all files and folders in sub_directory_path to the AWS S3 bucket bucket_name.

    Calls [bucket_exists(), move_all_files_and_permissions()]
    in order (only this function will be called directly in main.py).

    - sub_directory_path must be a valid path in local directory UNDER bucket_directory_path
    (i.e. the folder at bucket_directory_path must contain sub_directory_path)
    - bucket_directory_path corresponds to the S3 bucket bucket_name
    - bucket_name must lead to an existing bucket in AWS S3
    - permissions will be applied to the AWS S3 bucket bucket_name to match the
    permissions in directory_path
    """
    if not os.path.exists(sub_directory_path):
        print("directory path does not exist")
        return None
    if not bucket_exists(bucket_name):
        print("bucket does not exist")
        return None

    global bucket_directory_path
    bucket_directory_path = input("Enter the Bucket Directory Path corresponding to the bucket " + bucket_name + ": ")

    if not os.path.exists(bucket_directory_path):
        print("bucket directory path does not exist")
        return None
    if not os.path.isdir(bucket_directory_path):
        print("Bucket Directory Path is not a directory path")
        return None
    if bucket_directory_path not in sub_directory_path:
        print("File/Folder not found in Bucket Directory Path. Please move the file/folder to " + bucket_directory_path)
        return None

    # All folders related to a file get automatically added when the file is added
    if not os.path.isdir(sub_directory_path):
        move_file_and_permissions(sub_directory_path, bucket_name)
        return None

    move_all_files_and_permissions(sub_directory_path, bucket_name)


def bucket_exists(bucket_name: str) -> bool:
    """
    Returns True if bucket_name leads to an existing bucket in AWS S3 and False otherwise.

    - if the user does not have the permission to access the bucket, the program will return False (subject to change)
    - any errors will result in the program to return False, but will log different error messages (subject to change)
    """
    try:
        s3.meta.client.head_bucket(Bucket=bucket_name)
        return True
    except ClientError as e:
        # If a client error is thrown, then check that it was a 404 error.
        # If it was a 404 error, then the bucket does not exist.
        # If it was a 403 error, then access permission is needed.
        error_code = int(e.response["Error"]["Code"])
        if error_code == 403:
            # if the permission is denied pretend the bucket does not exist to prevent errors later on
            print("403 Permission Denied")
            return False
        elif error_code == 404:
            print("404 Does not exist")
            return False
        else:
            print("Some other error")
            return False


def move_all_files_and_permissions(directory_path: str, bucket_name: str):
    """
    Moves all files in directory_path to bucket_name and applies all permissions
    (recursively).

    Calls [move_file_and_permissions()] in order.

    - Not including the folder at directory_path
    """
    try:
        if os.path.isdir(directory_path):
            all_files = os.listdir(directory_path)
        else:
            all_files = []
    except PermissionError:
        print("Permission denied: " + directory_path)
    except TypeError:
        print(traceback.format_exc())
    except FileNotFoundError:
        print(traceback.format_exc())
    except InterruptedError:
        print(traceback.format_exc())
    except MemoryError:
        print(traceback.format_exc())
    except TimeoutError:
        print(traceback.format_exc())
    except OSError:
        print(traceback.format_exc())
    except:
        print(traceback.format_exc())
    else:
        for file in all_files:
            file_path = os.path.join(directory_path, file)
            move_file_and_permissions(file_path, bucket_name)
            move_all_files_and_permissions(file_path, bucket_name)


def move_file_and_permissions(file_path: str, bucket_name: str):
    """
    Moves the file in file_path to the AWS S3 bucket bucket_name while preserving
    the directory structure outlined in file_path, then calls check_file_security().

    Calls [check_file_security()] in order.

    - if file_path leads to an empty folder, S3 will automatically NOT add the folder so a log will be printed,
    but no exceptions will be raised
    """
    s3_path = get_s3_path(file_path, bucket_name)
    s3_file.put(file_path, s3_path)
    check_file_security(file_path, bucket_name)

    tail, file_name = os.path.split(file_path)

    # To account for S3 not adding Empty folders
    try:
        if os.path.isdir(file_path) and not os.listdir(file_path):
            print(file_name + " is an Empty Folder, so it was NOT added to the bucket")
        else:
            print(file_name + " was added to bucket " + bucket_name + " at " + s3_path)
    except:
        print("Access Denied for: " + file_name)


def get_s3_path(file_path: str, bucket_name: str) -> str:
    """
    Returns a valid s3_path in the form: s3://bucket_name/s3_directory_path/
    where s3_directory_path is derived from the file_path

    - s3_path is the same as the S3 url, the name change is to indicate a different use case
    """
    s3_directory_path = file_path.replace(bucket_directory_path, "")
    s3_path = "s3://" + bucket_name + s3_directory_path + "/"
    s3_path = s3_path.replace("\\", "/")
    return s3_path


def check_file_security(file_path: str, bucket_name: str):
    """
    Checks and modifies all permissions in corresponding file in bucket_name to match permissions in
    file_path (recursively for each user/group in file_path).

    - ignores and logs/raises an exception to all users and groups in file_path,
    but not in bucket_name
    """
    try:
        dacl = win32security.GetNamedSecurityInfo(
            file_path,
            win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION
        ).GetSecurityDescriptorDacl()

        for n_ace in range(dacl.GetAceCount()):
            user_exists = True
            is_user = True
            policy = False
            ace = dacl.GetAce(n_ace)
            (ace_type, ace_flags) = ace[0]
            if ace_type in CONVENTIONAL_ACES:
                mask, sid = ace[1:]
            else:
                mask, object_type, inherited_object_type, sid = ace[1:]
            try:
                name, domain, type = win32security.LookupAccountSid(None, sid)
                if type != 1:
                    is_user = False
            except:
                name = switch_sid(sid)
                is_user = False

            if CONVENTIONAL_ACES.get(ace_type, "OTHER") == "ALLOW":
                policy = True

            if is_user and policy:
                try:
                    iam.get_user(UserName=name)
                except:
                    if_create = input("Create user of not[Y/N]: ")
                    if if_create == "Y":
                        create_user(name)
                    else:
                        user_exists = False
            elif policy:
                try:
                    iam.get_group(GroupName=name)
                except:
                    if_create = input("Create user: " + name + "? [Y/N]: ")
                    if if_create == "Y":
                        create_group(name)
                    else:
                        user_exists = False

            if user_exists and policy:
                try:
                    get_policy(name, is_user)
                except:
                    create_inline_policy(name, bucket_name, is_user)

                update_inline_policy(name, file_path, bucket_name, switch_permission(mask), is_user)
    except ClientError as e:
        # AllAccessDisabled error == bucket not found
        logging.error(e)
    except:
        print(traceback.format_exc())


def create_user(user_name: str):
    result = iam.create_user(UserName=user_name)
    return result


def create_group(group_name: str):
    result = iam.create_group(GroupName=group_name)
    return result


def get_policy(user_name: str, is_user: bool):
    if is_user:
        result = iam.get_user_policy(UserName=user_name, PolicyName=user_name)
    else:
        result = iam.get_group_policy(GroupName=user_name, PolicyName=user_name)
    return result


def create_inline_policy(user_name: str, bucket_name: str, is_user: bool):
    default_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject*",
                ],
                "Resource": [
                    "arn:aws:s3:::" + bucket_name + "/default_policy.txt",
                ]
            },
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetObject*",
                    "s3:PutObject*",
                ],
                "Resource": [
                    "arn:aws:s3:::" + bucket_name + "/default_policy.txt",
                ]
            }
        ]
    }

    if is_user:
        result = iam.put_user_policy(
            PolicyName=user_name,
            UserName=user_name,
            PolicyDocument=json.dumps(default_policy),
        )
    else:
        result = iam.put_group_policy(
            GroupName=user_name,
            PolicyName=user_name,
            PolicyDocument=json.dumps(default_policy),
        )
    return result


def update_inline_policy(user_name: str, file_path: str, bucket_name: str, permission: int, is_user: bool):
    object_path = file_path.replace(bucket_directory_path, "")
    object_name = object_path.replace("\\", "/")
    original = get_policy(user_name, is_user)["PolicyDocument"]
    if os.path.isdir(file_path):
        new_resource = "arn:aws:s3:::" + bucket_name + object_name + "/"
    else:
        new_resource = "arn:aws:s3:::" + bucket_name + object_name

    if new_resource not in original["Statement"][permission]["Resource"]:
        original["Statement"][permission]["Resource"].append(new_resource)

    if is_user:
        result = iam.put_user_policy(
            PolicyName=user_name,
            UserName=user_name,
            PolicyDocument=json.dumps(original),
        )
    else:
        result = iam.put_group_policy(
            GroupName=user_name,
            PolicyName=user_name,
            PolicyDocument=json.dumps(original),
        )
    return result


def switch_permission(mask):
    if (mask == 0x001F01FF or
            mask == 0x000301BF or
            mask == 0x00000116 or
            mask == 0x0012019F or
            mask == 0x001201BF or
            mask == 0x001301BF):
        result = 1
    else:
        result = 0
    return result

