"""
This file needs to have the user input a path and loop through every file using Depth First Search
and return the security permissions of each file in the path as a txt file.
"""

import os

directory_path = None


def obtain_directory_path():
    """
    Asks for a user input and assigns the input to directory_path.
    """
    global directory_path
    directory_path = input("Enter Directory Path: ")

    
def loop_through_files(path: str):
    """
    Given the directory path, this function loops through all the files and folders in the path
    using Depth First Search principles
    """
    
