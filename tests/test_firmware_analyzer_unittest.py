import unittest

from src import firmware_analyzer

import zipfile

ORDERED_DICT = 'ordered_dict'

FILE_NAME = 'file_name'


class TestFirmwareAnalyzer(unittest.TestCase):

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

    def test_handle_file(self):
        directory_path_file = zipfile.ZipFile("resources/tests.zip", "r")
        # no tokens tests:
        test_case = 'noTokenTextFile.txt'
        result = firmware_analyzer.handle_file(directory_path_file, test_case)
        self.assertIsNone(result)
        test_case = 'noTokenBin.dll'
        result = firmware_analyzer.handle_file(directory_path_file, test_case)
        self.assertIsNone(result)

        # # single tokens tests:
        # test_case = 'singleTokenText.txt'
        # result = firmware_analyzer.handle_file(directory_path_file, test_case)
        # self.assertEqual(result['file_name'], test_case)
        # self.assertEqual(result['ordered_dict'][0], 'token')
        # self.assertEqual(len(result['ordered_dict']), 1)
        # test_case = 'singleTokenBin'
        # result = firmware_analyzer.handle_file(directory_path_file, test_case)
        # self.assertEqual(result['file_name'], test_case)
        # self.assertEqual(result['ordered_dict'][0], 'token')
        # self.assertEqual(len(result['ordered_dict']), 1)
        # test_case = 'singleTokenTextAsPartOfAWord'
        # self.assertEqual(result['file_name'], test_case)
        # self.assertEqual(result['ordered_dict'][0], 'token')
        # self.assertEqual(len(result['ordered_dict']), 1)

    def test_process_file_content(self):
        # no tokens tests:
        self.validateEmpty(b'', "empty")
        self.validateEmpty(b'test', "no_token")
        self.validateEmpty(b'<Tkn999AAAATkn>', "almost_like_token_missing_letter")
        self.validateEmpty(b'<Tkn999AAAAAAkn>', "almost_like_token_missing_T")
        self.validateEmpty(b'<Tkn9999AAAAATkn>', "almost_like_token_too_much_digits")
        # single tokens tests:
        self.validateContentResult(b'<Tkn999AAAAATkn>', b'<Tkn999AAAAATkn>', 'use_case_single_token')
        self.validateContentResult(b'start<Tkn999AAAAATkn>', b'<Tkn999AAAAATkn>', 'use_case_token_with_prefix')
        self.validateContentResult(b'<Tkn999AAAAATkn>end', b'<Tkn999AAAAATkn>', 'use_case_token_with_suffix')
        self.validateContentResult(b'start<Tkn999AAAAATkn>middle', b'<Tkn999AAAAATkn>',
                                   'use_case_token_with_prefix_suffix')
        self.validateContentResult(b'<Tkn999AAAAATkn>start <Tkn999AAAAATkn>end', b'<Tkn999AAAAATkn>',
                                   'use_case_single_token_multi', 2)
        self.validateContentResult(b'<Tkn999AAAAATkn>start <Tkn999AAAAATkn>end <Tkn999AAAAATkn>',
                                   b'<Tkn999AAAAATkn>', 'use_case_single_token_multi', 3)
        # multi tokens tests:
        # Also test order occurrences and then name -> order from low to high
        self.validateContentResult(b'<Tkn999AABAATkn>start <Tkn999AAAAATkn>end <Tkn999AAAAATkn>',
                                   b'<Tkn999AAAAATkn>', 'use_case_multi_token', 2, 2, 1)
        self.validateContentResult(b'<Tkn999AABAATkn>start <Tkn999AAAAATkn>end <Tkn999AAAAATkn>',
                                   b'<Tkn999AABAATkn>', 'use_case_multi_token', 1, 2, 0)
        self.validateContentResult(b'<Tkn999AAAAATkn>start <Tkn999AABAATkn> <Tkn999AABAATkn>end <Tkn999AAAAATkn>',
                                   b'<Tkn999AAAAATkn>', 'use_case_multi_token_same_number_of_occurrences', 2, 2, 0)
        self.validateContentResult(b'<Tkn999AAAAATkn>start <Tkn999AABAATkn> <Tkn999AABAATkn>end <Tkn999AAAAATkn>',
                                   b'<Tkn999AABAATkn>', 'use_case_multi_token_same_number_of_occurrences', 2, 2, 1)

    def validateEmpty(self, b, empty):
        result = firmware_analyzer.process_file_content(empty, b)
        self.assertIsNone(result)

    def validateContentResult(self, content, token, use_case, occurrences=1, number_of_tokens=1, token_index=0):
        result = firmware_analyzer.process_file_content(use_case, content)
        self.assertEqual(result[FILE_NAME], use_case)
        self.assertEqual(len(result[ORDERED_DICT]), number_of_tokens)
        self.assertEqual(list(result[ORDERED_DICT].keys())[token_index], token)
        self.assertEqual(result[ORDERED_DICT].get(token), occurrences)


if __name__ == '__main__':
    unittest.main()
