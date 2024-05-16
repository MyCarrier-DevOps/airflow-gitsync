import unittest
import tempfile
import os
import shutil
from pathlib import Path
from airflow_gitsync import repo_cleanup


class TestRepoCleanup(unittest.TestCase):
    def setUp(self):
        self.repo_dir = tempfile.mkdtemp()

    def test_repo_cleanup(self):
        # Create a file and a directory inside repo_dir
        file_path = Path(self.repo_dir) / 'test_file'
        dir_path = Path(self.repo_dir) / 'test_dir'

        file_path.touch()
        dir_path.mkdir()

        self.assertTrue(file_path.exists())
        self.assertTrue(dir_path.exists())

        # Run repo_cleanup
        repo_cleanup(self.repo_dir)

        # Check if the file and directory are removed
        self.assertFalse(file_path.exists())
        self.assertFalse(dir_path.exists())

    def tearDown(self):
        shutil.rmtree(self.repo_dir)


if __name__ == "__main__":
    unittest.main()