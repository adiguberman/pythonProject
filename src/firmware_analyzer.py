"""
Firmware Analyzer

Special authentication tokens are in the following format:
Starting with "<Tkn" then later 3 digits, 5 English capital letters followed by a
"Tkn>". For example: <Tkn435JFIRKTkn>

This script receives a path to a zip file on the disk (the firmware file) and a path to a CSV file output.
Find the above pattern in all the files under the extracted file system of the zip file
(recursively in all the folders underneath to) and report the results into the
output CSV in the following format:

Path - The relative path of the found file to the location of the extracted
zip file.

Token - The identified token string

Occurrences - The number of occurrences of the Token inside the file path

The results are sorted by (Path, Occurrences, Token)

Also the script print to the screen the total findings of each token in all of the files.
For example if token <Tkn435JFIRKTkn> was found only in f1< 5 times and in f2 <3 times it should print <Tkn435JFIRKTkn> : 8
"""

import zipfile
import re
import csv
import collections
import concurrent.futures
import argparse

DECODE_FORMAT = 'ascii'
WRITE_MODE = 'w'
READ_MODE = "r"
NUMBER_OF_THREADS = 5
MAX_TIMEOUT = 3600  # 1 Hour


def parse_input():
    """parse input from the user
        Returns:
        list:Returning list of arguments
       """
    parser = argparse.ArgumentParser(prog='firmware_analyzer',
                                     description='special authentication tokens collector')
    parser.add_argument('directory_path', help="path to a zip file on the disk (the firmware file)")
    parser.add_argument('csv_output_path', help="path to a CSV file output")
    parser.add_argument('-number_of_threads', help="number of threads", type=int, default=NUMBER_OF_THREADS)
    return parser.parse_args()


def analyze_firmware(directory_path, csv_output_path, number_of_threads):
    """Reports to the csv output path all the found files and token information
        Parameters:
        directory_path (string): zip file on the disk (the firmware file)
        csv_output_path (string): path to a CSV file output
        number_of_threads (int): The maximum number of threads to process the file system
       """
    # empty dictionaries
    token_occurrences_dict = {}  # mapping between token to occurrences
    path_token_occurrences_dict = {}  # mapping between file name token to occurrences

    process_files_under_zip_file(directory_path, token_occurrences_dict, path_token_occurrences_dict, number_of_threads)

    create_output(token_occurrences_dict, path_token_occurrences_dict, csv_output_path)


def process_files_under_zip_file(directory_path, token_occurrences_dict, path_occurrences_token_dict,
                                 number_of_threads):
    """go over the files archived in zip file on the disk (the firmware file)
       and orchestrate the process of the files
       Updates dictionaries with the results
        Parameters:
        directory_path (string): zip file on the disk (the firmware file)
        token_occurrences_dict (dictionary): mapping between token to occurrences
        path_occurrences_token_dict (dictionary): mapping between token to occurrences
        number_of_threads (int): The maximum number of threads that can be used to execute process files.
       """
    with concurrent.futures.ThreadPoolExecutor(number_of_threads) as executor:
        # The thread poll is being used only for processing the files - reduce IO/CPU
        # The strategy is to process as many files as you can, and afterwards parse each file's result to major
        # dictionaries.
        # pros:
        # There is no locking whatsoever (no need to update common resources) in the most expensive compute action
        # (processing the files)
        # cons:
        # 1. Each Thread upload a file to the memory (can cause out of memory issues) - Note: number of threads is a
        # user's input parameter
        # 2. All the results of the executed processes of each file are saved in "futures" until all of the files were
        # scanned, this can cause out of memory issues. we assume that holding the data and consuming this memory
        # penalty is better then locking the IO processing action and spending CPU time.
        # TBD: is there a need to add a option to config the other strategy were each thread updates the dictionaries.
        # Out of scope.
        directory_path_file = zipfile.ZipFile(directory_path, READ_MODE)
        future_to_file_name = {}
        for file_name in directory_path_file.namelist():
            # out of scope - monitor threads, no logging
            future_to_file_name[executor.submit(handle_file, directory_path_file=directory_path_file,
                                                file_name=file_name)] = file_name
        for future in concurrent.futures.as_completed(future_to_file_name, MAX_TIMEOUT):
            # Out of scope - error is not handled as there is no monitor/logging
            file_name = future_to_file_name[future]
            try:
                result = future.result()
            except Exception as exc:
                print('%r generated an exception: %s' % (file_name, exc))
            else:
                # no match token
                if result and result['ordered_dict']:
                    path_occurrences_token_dict[result['file_name']] = result['ordered_dict']
                    for k, v in result['ordered_dict'].items():
                        token_occurrences_dict = update_dict(token_occurrences_dict, k, v)


def handle_file(directory_path_file, file_name):
    """Open a file from the archived zip, and process it. Find the above pattern and
    return a dictionary of token to occurrences in the processed file.
        Parameters:
                directory_path_file (ZipFile): zip file on the disk (the firmware file)
                file_name (string): file that will be process
        Returns:
        OrderedDict:Returning Ordered dictionary of token to occurrences Ordered by occurrences and then token (order
        from low to high, dictionary that remembers insertion order)
        file_name:Returning file name that was scanned
       """
    with directory_path_file.open(file_name, READ_MODE) as file:
        file_content = file.read()
        ordered_dict = process_file_content(file_content)
        if ordered_dict:
            return {'file_name': file_name, 'ordered_dict': ordered_dict}


def process_file_content(file_content):
    """Find the above pattern and return a dictionary of token to occurrences in the processed file.
        Parameters:
                file_content (binary): file content that will be process
        Returns:
        OrderedDict:Returning Ordered dictionary of token to occurrences Ordered by occurrences and then token (order
        from low to high, dictionary that remembers insertion order)
        file_name:Returning file name that was scanned
       """
    file_dict = {}
    match = re.findall(b'<Tkn[0-9][0-9][0-9][A-Z][A-Z][A-Z][A-Z][A-Z]Tkn>', file_content)
    if match:
        for token in match:
            file_dict = update_dict(file_dict, token)
        # OrderedDict - Dictionary that remembers insertion order
        # Sort by occurrences and then bt token - order from low to high
        return collections.OrderedDict(sorted(file_dict.items(), key=lambda x: (x[1], x[0])))


def update_dict(dictionary, key, size=1):
    """update dictionary by adding size to value per key (used for counting occurrences per token)
        Parameters:
        dictionary (dictionary): value per key  (occurrences per token)
        key (string): key
        size (int): the amount to use in order to update the counter (default 1)

        Returns:
        dictionary:Returning updated dictionary
       """
    occurrences = dictionary.get(key)
    if occurrences is None:
        occurrences = size
    else:
        occurrences = occurrences + size
    dictionary[key] = occurrences
    return dictionary


def create_output(token_occurrences_dict, path_occurrences_token_dict, csv_output_path):
    """creates the output file and the output text on the screen

        Parameters:
        token_occurrences_dict (dictionary): mapping between token to occurrences
        path_occurrences_token_dict (dictionary): mapping between token to occurrences
        csv_output_path (string): path to a CSV file output
       """
    with open(csv_output_path, WRITE_MODE, newline='') as file:
        writer = csv.writer(file)
        # OrderedDict - Dictionary that remembers insertion order
        # Sort by path order from low to high
        path_token_occurrences_dict_ordered = collections.OrderedDict(
            sorted(path_occurrences_token_dict.items()))
        for key, value in path_token_occurrences_dict_ordered.items():
            for k, v in value.items():
                writer.writerow([key, v, k.decode(DECODE_FORMAT)])
    # print dictionary without brackets
    print('\n'.join("{}: {}".format(k.decode(DECODE_FORMAT), v) for k, v in token_occurrences_dict.items()))


if __name__ == '__main__':
    args = parse_input()
    analyze_firmware(args.directory_path, args.csv_output_path, args.number_of_threads)
