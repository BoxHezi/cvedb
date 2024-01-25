from tqdm import tqdm
import git

from ..utils import pathutils

# GITHUB NVD JSON FEEDS Repo: https://github.com/fkie-cad/nvd-json-data-feeds
NVD_FEEDS_REPO = "https://github.com/fkie-cad/nvd-json-data-feeds.git"
# This project uses and redistributes data from the NVD API but is not endorsed or certified by the NVD.

"""
reference: https://stackoverflow.com/questions/51045540/python-progress-bar-for-git-clone
add Clone Progress bar
"""
class CloneProgress(git.RemoteProgress):
    def __init__(self):
        super().__init__()
        self.pbar = tqdm()

    def update(self, op_code, cur_count, max_count=None, message=''):
        if op_code & self.BEGIN:
            desc = f"{self._cur_line[:self._cur_line.rfind(':')]}{': ' + message if message else ''}"
            self.pbar.set_description(desc)

        self.pbar.total = max_count
        self.pbar.n = cur_count
        self.pbar.refresh()

        if op_code & self.END:
            print()


class NVDFeedsHandler:
    def __init__(self):
        pathutils.create_path(pathutils.DEFAULT_PROJECT_DIR)
        self.local_repo_path = pathutils.DEFAULT_PROJECT_DIR / "NVD-JSON-Data-Feeds"

        if not pathutils.path_exists(self.local_repo_path):
            print("Cloning Repo ...")
            self.clone_to_local()
            print("DONE")

        self.repo = git.Repo(self.local_repo_path)

    def clone_to_local(self):
        git.Repo.clone_from(NVD_FEEDS_REPO, self.local_repo_path, progress=CloneProgress())
