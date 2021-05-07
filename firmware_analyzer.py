import zipfile
import re
import io
import csv
import collections
import concurrent.futures
import argparse

WRITE_MODE = 'w'
READ_MODE = "r"
NUMBER_OF_THREADS = 5
# Pattern can be a part of a word?
PATTERN = "<Tkn[0-9][0-9][0-9][A-Z][A-Z][A-Z][A-Z][A-Z]Tkn>"


def analyze_firmware(directory_path, csv_output_path, number_of_threads):
    # empty dictionaries
    global_dict = {}
    path_occurrences_token_dict = {}

    travel_zip_file(directory_path, global_dict, path_occurrences_token_dict, number_of_threads)

    create_output(global_dict, path_occurrences_token_dict, csv_output_path)


def create_output(global_dict, path_occurrences_token_dict, csv_output_path):
    with open(csv_output_path, WRITE_MODE, newline='') as file:
        writer = csv.writer(file)
        path_occurrences_token_dict_ordered = collections.OrderedDict(sorted(path_occurrences_token_dict.items()))
        for key, value in path_occurrences_token_dict_ordered.items():
            for k, v in value.items():
                writer.writerow([key, v, k])
                print(key, v, k)
    print('\n'.join("{}: {}".format(k, v) for k, v in global_dict.items()))


def travel_zip_file(directory_path, global_dict, path_occurrences_token_dict, number_of_threads):
    with concurrent.futures.ThreadPoolExecutor(number_of_threads) as executor:
        futures = []
        directory_path_file = zipfile.ZipFile(directory_path, READ_MODE)
        for file_name in directory_path_file.namelist():
            futures.append(executor.submit(handle_file, directory_path_file=directory_path_file, file_name=file_name))
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            path_occurrences_token_dict[file_name] = result
            for k, v in result.items():
                update_dict(global_dict, k, v)


def handle_file(directory_path_file, file_name):
    file_dict = {}
    with directory_path_file.open(file_name, READ_MODE) as file:
        items_file = io.TextIOWrapper(file)
        for line in items_file:
            for word in line.split():
                z = re.match(PATTERN, word)
                if z:
                    token = z.string
                    update_dict(file_dict, token)
        return collections.OrderedDict(sorted(file_dict.items(), key=lambda x: (x[1], x[0]), reverse=True))


def update_dict(dict, string, size=1):
    number = dict.get(string)
    if number is None:
        number = size
    else:
        number = number + size
    dict[string] = number


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='firmware_analyzer',
                                     description='special authentication tokens collector')
    parser.add_argument('directory_path', help="path to a zip file on the disk (the firmware file)")
    parser.add_argument('csv_output_path', help="path to a CSV file output")
    parser.add_argument('-number_of_threads', help="number of threads", type=int, default=NUMBER_OF_THREADS)
    args = parser.parse_args()
    analyze_firmware(args.directory_path, args.csv_output_path, args.number_of_threads)
