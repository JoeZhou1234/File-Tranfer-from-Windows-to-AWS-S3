import os
import traceback
import win32security

# (For testing purposes)
test = open(r"C:\Users\Joe\test.txt", "w")
all_path_list = []
all_name_list = []

CONVENTIONAL_ACES = {
    win32security.ACCESS_ALLOWED_ACE_TYPE: "ALLOW",
    win32security.ACCESS_DENIED_ACE_TYPE: "DENY"
}


def obtain_directory_path():
    """
    Returns a valid directory path from the user input.
    If the user inputs a file path instead, then call obtain_file_permissions() and return None.
    """
    directory_path = input("Enter File or Directory Path: ")

    # check whether the path exists
    if not os.path.exists(directory_path):
        print("Path does not exist.")
        directory_path = None
    # check whether the path is a file
    elif os.path.isfile(directory_path):
        obtain_file_permissions(directory_path)
        directory_path = None

    return directory_path


def obtain_all_file_permissions(directory_path: str):
    """
    Note: directory_path must be a valid directory path and not a file path.

    Loops through all files and folders in directory_path and returns/prints each file or folder's permissions
    (including the permissions of the folder in directory_path) in the following format:

    Writes to a .txt file all files located in directory_path and their respective permissions in the following format
    (For testing purposes):
    [File Path]
    ["ALLOW"/"DENY"] [Group/User 1] [Permission Mask 1]
    ["ALLOW"/"DENY"] [Group/User 2] [Permission Mask 2]
    ["ALLOW"/"DENY"] [Group/User 3] [Permission Mask 3]

    [File Path]
    ...

    Returns a list of all file paths, all_path_list, and a list of all file names, all_name_list. (For testing purposes)
    """

    # get the files and directories present in a given path
    try:
        all_files = os.listdir(directory_path)
    except PermissionError:
        print("Permission denied: " + directory_path)
        # (For testing purposes)
        test.write(directory_path)
        test.write("\n")
        test.write("Permission denied")
        test.write("\n")
        test.write("\n")

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
        # (For testing purposes)
        all_path_list.append(directory_path)
        all_name_list.append(os.path.basename(directory_path))

        obtain_file_permissions(directory_path)

        # loop through all files and directories
        for file in all_files:
            # get the path of each of the files and directories
            file_path = os.path.join(directory_path, file)
            # check whether each path is an existing directory or not, if it, do recursion
            if os.path.isdir(file_path):
                obtain_all_file_permissions(file_path)
            else:
                # (For testing purposes)
                all_path_list.append(file_path)
                all_name_list.append(file)

                obtain_file_permissions(file_path)
    # (For testing purposes)
    finally:
        return all_path_list, all_name_list


def obtain_file_permissions(file_path: str):
    """
    Returns/prints the permissions of the file or folder in file_path in the following format:

    Writes to a .txt file the file_path and the file permissions in the following format (For testing purposes):
    [File Path]
    ["ALLOW"/"DENY"] [Group/User 1] [Permission Mask 1]
    ["ALLOW"/"DENY"] [Group/User 2] [Permission Mask 2]
    ["ALLOW"/"DENY"] [Group/User 3] [Permission Mask 3]
    ["\n"]

    Prints the information being written to the .txt file. (For testing purposes)
    """
    try:
        # (For testing purposes)
        test.write(str(file_path))
        test.write("\n")

        print(file_path)

        dacl = win32security.GetNamedSecurityInfo(
            file_path,
            win32security.SE_FILE_OBJECT,
            win32security.DACL_SECURITY_INFORMATION
        ).GetSecurityDescriptorDacl()

        for n_ace in range(dacl.GetAceCount()):
            ace = dacl.GetAce(n_ace)
            (ace_type, ace_flags) = ace[0]
            if ace_type in CONVENTIONAL_ACES:
                mask, sid = ace[1:]
            else:
                mask, object_type, inherited_object_type, sid = ace[1:]
            try:
                name, domain, type = win32security.LookupAccountSid(None, sid)
            except:
                name = "no corresponding account name"
            print(
                CONVENTIONAL_ACES.get(ace_type, "OTHER"),
                sid,
                name,
                mask
            )
            # (For testing purposes)
            test.write(str(CONVENTIONAL_ACES.get(ace_type, "OTHER")) + " " + str(sid) + " " + str(name) + " " + str(
                switch(mask)))
            test.write("\n")
        # (For testing purposes)
        test.write("\n")

        print("")

    except:
        print(traceback.format_exc())


# (For testing purposes)
def switch(mask: int):
    """
    Return the permission mask as a string.
    """
    return {
        0x001F01FF: "FullControl(Single)",
        0x000301BF: "Modify(Single)",
        0x000200A9: "ReadAndExecute(Single)",
        0x00020089: "Read(Single)",
        0x00000116: "Write(Single)",
        0x001200A9: "ReadAndExecute(Combo)",
        0x00120089: "Read(Combo)",
        0x0012019F: "Read,Write(Combo)",
        0x001201BF: "ReadAndExecute,Write(Combo)",
        0x001301BF: "ReadAndExecute,Modify,Write(Combo)",
        0x40: "Permission Denied"
    }.get(mask, "SpecialPermissions")
