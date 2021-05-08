import unittest
from src import firmware_analyzer
import zipfile
from collections import OrderedDict
from unittest.mock import patch

ORDERED_DICT = 'ordered_dict'
FILE_NAME = 'file_name'


class TestFirmwareAnalyzer(unittest.TestCase):

    @patch('builtins.open')
    @patch('builtins.print')
    def test_analyze_firmware_no_folder(self, mock_print, mock_open):
        fake_file_path = 'file/path/mock'

        firmware_analyzer.analyze_firmware("resources/tests.zip", fake_file_path, 1)
        self.assertEqual(str(mock_print.mock_calls), "[call('<Tkn998QYXPKTkn>: 2')]")
        calls = "[call('file/path/mock', 'w', newline=''),\n " \
                "call().__enter__(),\n call().__enter__().write('TokenBin.dll,1,<Tkn998QYXPKTkn>\\r\\n'),\n " \
                "call().__enter__().write('TokenText.txt,1,<Tkn998QYXPKTkn>\\r\\n'),\n " \
                "call().__exit__(None, None, None)]"
        self.assertEqual(str(mock_open.mock_calls), calls)

    @patch('builtins.open')
    @patch('builtins.print')
    def test_analyze_firmware_folder(self, mock_print, mock_open):
        fake_file_path = 'file/path/mock'
        firmware_analyzer.analyze_firmware("resources/testsWithFolders.zip", fake_file_path, 1)

        self.assertEqual(str(mock_print.mock_calls), "[call('<Tkn998QYXPKTkn>: 4')]")
        calls = "[call('file/path/mock', 'w', newline=''),\n " \
                "call().__enter__(),\n " \
                "call().__enter__().write('TokenBin.dll,1,<Tkn998QYXPKTkn>\\r\\n'),\n " \
                "call().__enter__().write('TokenText.txt,1,<Tkn998QYXPKTkn>\\r\\n'),\n " \
                "call().__enter__().write('folder/TokenBin.dll,1,<Tkn998QYXPKTkn>\\r\\n'),\n " \
                "call().__enter__().write('folder/TokenText.txt,1,<Tkn998QYXPKTkn>\\r\\n'),\n " \
                "call().__exit__(None, None, None)]"

        self.assertEqual(str(mock_open.mock_calls), calls)

    @patch('builtins.open')
    @patch('builtins.print')
    def test_create_output_no_folder(self, mock_print, mock_open):
        fake_file_path = 'file/path/mock'
        dict1 = {b'<Tkn998QYXPKTkn>': 2}
        dict2 = {'TokenText.txt': OrderedDict([(b'<Tkn998QYXPKTkn>', 1)]),
                 'TokenBin.dll': OrderedDict([(b'<Tkn998QYXPKTkn>', 1)])}
        firmware_analyzer.create_output(dict1, dict2, fake_file_path)
        self.assertEqual(str(mock_print.mock_calls), "[call('<Tkn998QYXPKTkn>: 2')]")
        calls = "[call('file/path/mock', 'w', newline=''),\n " \
                "call().__enter__(),\n call().__enter__().write('TokenBin.dll,1,<Tkn998QYXPKTkn>\\r\\n'),\n " \
                "call().__enter__().write('TokenText.txt,1,<Tkn998QYXPKTkn>\\r\\n'),\n " \
                "call().__exit__(None, None, None)]"
        self.assertEqual(str(mock_open.mock_calls), calls)

    @patch('builtins.open')
    @patch('builtins.print')
    def test_create_output_with_folder(self, mock_print, mock_open):
        fake_file_path = 'file/path/mock'
        dict1 = {b'<Tkn998QYXPKTkn>': 4}
        dict2 = {'TokenText.txt': OrderedDict([(b'<Tkn998QYXPKTkn>', 1)]),
                 'TokenBin.dll': OrderedDict([(b'<Tkn998QYXPKTkn>', 1)]),
                 'folder/TokenBin.dll': OrderedDict([(b'<Tkn998QYXPKTkn>', 1)]),
                 'folder/TokenText.txt': OrderedDict([(b'<Tkn998QYXPKTkn>', 1)])}
        firmware_analyzer.create_output(dict1, dict2, fake_file_path)
        self.assertEqual(str(mock_print.mock_calls), "[call('<Tkn998QYXPKTkn>: 4')]")
        calls = "[call('file/path/mock', 'w', newline=''),\n " \
                "call().__enter__(),\n " \
                "call().__enter__().write('TokenBin.dll,1,<Tkn998QYXPKTkn>\\r\\n'),\n " \
                "call().__enter__().write('TokenText.txt,1,<Tkn998QYXPKTkn>\\r\\n'),\n " \
                "call().__enter__().write('folder/TokenBin.dll,1,<Tkn998QYXPKTkn>\\r\\n'),\n " \
                "call().__enter__().write('folder/TokenText.txt,1,<Tkn998QYXPKTkn>\\r\\n'),\n " \
                "call().__exit__(None, None, None)]"

        self.assertEqual(str(mock_open.mock_calls), calls)

    def test_process_files_under_zip_file_no_folders(self):
        dict1, dict2 = {}, {}
        firmware_analyzer.process_files_under_zip_file("resources/tests.zip", dict1, dict2, 1)
        self.assertEqual(len(dict1), 1)
        self.assertEqual(dict1.get(b'<Tkn998QYXPKTkn>'), 2)
        self.assertEqual(len(dict2), 2)
        file = dict2.get('TokenText.txt')
        self.assertEqual(file.get(b'<Tkn998QYXPKTkn>'), 1)
        file = dict2.get('TokenBin.dll')
        self.assertEqual(file.get(b'<Tkn998QYXPKTkn>'), 1)

    def test_process_files_under_zip_file_file_not_found(self):
        with self.assertRaises(FileNotFoundError):
            firmware_analyzer.process_files_under_zip_file('dontExist', {}, {}, 1)

    def test_process_files_under_zip_file_with_folders(self):
        dict1, dict2 = {}, {}
        firmware_analyzer.process_files_under_zip_file("resources/testsWithFolders.zip", dict1, dict2, 1)
        self.assertEqual(len(dict1), 1)
        self.assertEqual(dict1.get(b'<Tkn998QYXPKTkn>'), 4)
        self.assertEqual(len(dict2), 4)
        file = dict2.get('TokenText.txt')
        self.assertEqual(file.get(b'<Tkn998QYXPKTkn>'), 1)
        file = dict2.get('TokenBin.dll')
        self.assertEqual(file.get(b'<Tkn998QYXPKTkn>'), 1)
        file = dict2.get('folder/TokenText.txt')
        self.assertEqual(file.get(b'<Tkn998QYXPKTkn>'), 1)
        file = dict2.get('folder/TokenBin.dll')
        self.assertEqual(file.get(b'<Tkn998QYXPKTkn>'), 1)

    def test_update_dict(self):
        res1 = {}
        firmware_analyzer.update_dict(res1, b'test')
        self.assertEqual(res1.get(b'test'), 1)

        firmware_analyzer.update_dict(res1, b'test')
        self.assertEqual(res1.get(b'test'), 2)

        res2 = {}
        init_size = 15
        firmware_analyzer.update_dict(res2, b'test', init_size)
        self.assertEqual(res2.get(b'test'), init_size)

        delta = 16
        firmware_analyzer.update_dict(res2, b'test', delta)
        self.assertEqual(res2.get(b'test'), init_size + delta)

    def test_handle_file_no_tokens(self):
        directory_path_file = zipfile.ZipFile("resources/tests.zip", "r")
        # no tokens tests:
        test_case = 'noTokenTextFile.txt'
        result = firmware_analyzer.handle_file(directory_path_file, test_case)
        self.assertIsNone(result)
        test_case = 'noTokenBin.dll'
        result = firmware_analyzer.handle_file(directory_path_file, test_case)
        self.assertIsNone(result)

    def test_handle_file_with_tokens(self):
        directory_path_file = zipfile.ZipFile("resources/tests.zip", "r")
        # Tokens tests:
        test_case = 'TokenText.txt'
        result = firmware_analyzer.handle_file(directory_path_file, test_case)
        self.assertEqual(result[FILE_NAME], test_case)
        self.assertEqual(list(result[ORDERED_DICT].keys())[0], b'<Tkn998QYXPKTkn>')
        self.assertEqual(len(result[ORDERED_DICT]), 1)
        test_case = 'TokenBin.dll'
        result = firmware_analyzer.handle_file(directory_path_file, test_case)
        self.assertEqual(result[FILE_NAME], test_case)
        self.assertEqual(list(result[ORDERED_DICT].keys())[0], b'<Tkn998QYXPKTkn>')
        self.assertEqual(len(result[ORDERED_DICT]), 1)

    def test_process_file_content_no_tokens(self):
        # no tokens tests:
        # empty
        self.validateEmpty(b'')
        # no_token
        self.validateEmpty(b'test')
        # almost_like_token_missing_letter
        self.validateEmpty(b'<Tkn999AAAATkn>')
        # almost_like_token_missing_T
        self.validateEmpty(b'<Tkn999AAAAAAkn>')
        # almost_like_token_too_much_digits
        self.validateEmpty(b'<Tkn9999AAAAATkn>')

    def test_process_file_content_single_token(self):
        # single tokens tests:
        # use_case_single_token
        self.validateContentResult(b'<Tkn999AAAAATkn>', b'<Tkn999AAAAATkn>')
        # use_case_token_with_prefix
        self.validateContentResult(b'start<Tkn999AAAAATkn>', b'<Tkn999AAAAATkn>')
        # use_case_token_with_suffix
        self.validateContentResult(b'<Tkn999AAAAATkn>end', b'<Tkn999AAAAATkn>')
        # use_case_token_with_prefix_suffix
        self.validateContentResult(b'start<Tkn999AAAAATkn>middle', b'<Tkn999AAAAATkn>')
        # use_case_single_token_multi
        self.validateContentResult(b'<Tkn999AAAAATkn>start <Tkn999AAAAATkn>end', b'<Tkn999AAAAATkn>', 2)
        # use_case_single_token_multi
        self.validateContentResult(b'<Tkn999AAAAATkn>start <Tkn999AAAAATkn>end <Tkn999AAAAATkn>',
                                   b'<Tkn999AAAAATkn>', 3)

    def test_process_file_content_multi_tokens(self):
        # multi tokens tests:
        # Also test order occurrences and then name -> order from low to high
        # use_case_multi_token
        self.validateContentResult(b'<Tkn999AABAATkn>start <Tkn999AAAAATkn>end <Tkn999AAAAATkn>',
                                   b'<Tkn999AAAAATkn>', 2, 2, 1)
        # use_case_multi_token
        self.validateContentResult(b'<Tkn999AABAATkn>start <Tkn999AAAAATkn>end <Tkn999AAAAATkn>',
                                   b'<Tkn999AABAATkn>', 1, 2, 0)
        # use_case_multi_token_same_number_of_occurrences
        self.validateContentResult(b'<Tkn999AAAAATkn>start <Tkn999AABAATkn> <Tkn999AABAATkn>end <Tkn999AAAAATkn>',
                                   b'<Tkn999AAAAATkn>', 2, 2, 0)
        # use_case_multi_token_same_number_of_occurrences
        self.validateContentResult(b'<Tkn999AAAAATkn>start <Tkn999AABAATkn> <Tkn999AABAATkn>end <Tkn999AAAAATkn>',
                                   b'<Tkn999AABAATkn>', 2, 2, 1)

    def validateEmpty(self, empty):
        result = firmware_analyzer.process_file_content(empty)
        self.assertIsNone(result)

    def validateContentResult(self, content, token, occurrences=1, number_of_tokens=1, token_index=0):
        result = firmware_analyzer.process_file_content(content)
        self.assertEqual(len(result), number_of_tokens)
        self.assertEqual(list(result.keys())[token_index], token)
        self.assertEqual(result.get(token), occurrences)


if __name__ == '__main__':
    unittest.main()
