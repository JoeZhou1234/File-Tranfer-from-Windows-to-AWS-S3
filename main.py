"""
This is where all the code is executed.
"""

if __name__ == '__main__':

    # import get_permissions
    import move_files

    # (For testing purposes)
    bucket_name = "joe-test-bucket"
    directory_path = r"C:\Users\Joe\Test Sample"

    # directory_path = get_permissions.obtain_directory_path()
    # if directory_path != "":
    #     get_permissions.obtain_all_file_permissions(directory_path)

    # (For testing purposes)
    # get_permissions.test.close()

    # Test Part 1
    # move_files.move_local_to_s3(directory_path, bucket_name)

    # Test Part 2
    # sub_directory_path = r"C:\Users\joe\test.txt"
    # move_files.move_local_to_s3(sub_directory_path, bucket_name)

