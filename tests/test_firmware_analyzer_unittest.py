import unittest

from src import firmware_analyzer
import os
import zipfile


class TestSum(unittest.TestCase):

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
        directory_path_file = zipfile.ZipFile("resources/sampleBig.zip", "r")
        test_case = 'test_case1.txt'
        result = firmware_analyzer.handle_file(directory_path_file, test_case)
        print(os.path.join("../test.txt"))


if __name__ == '__main__':
    unittest.main()
