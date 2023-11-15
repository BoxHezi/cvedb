import git
from tqdm import tqdm

import pathutils

# CVE List V5 Github Repo: https://github.com/CVEProject/cvelistV5
CVE_LIST_V5_REPO = "git@github.com:CVEProject/cvelistV5.git"

"""
reference: https://stackoverflow.com/questions/51045540/python-progress-bar-for-git-clone
add Clone Progress bar
"""
class CloneProgress(git.RemoteProgress):
    def __init__(self) -> None:
        super().__init__()

    def update(self, *args):
        print(self._cur_line, end="\r")


class CvelistHandler:
    def __init__(self):
        self.config_path = pathutils.home_dir() / ".config/cvedb"
        pathutils.create_path(self.config_path)

        self.local_repo_path = self.config_path / "cvelistV5"

        if not pathutils.path_exists(self.local_repo_path):
            print("Cloning Repo...")
            self.clone_to_local()
        self.repo = git.Repo(self.local_repo_path)

    def clone_to_local(self):
        git.Repo.clone_from(CVE_LIST_V5_REPO, self.local_repo_path, progress=CloneProgress())

    def find_updated_files(self):
        origin = self.repo.remotes.origin
        origin.fetch()

        remote_hash = origin.refs.main.commit.hexsha

        updated_file = [item.a_path for item in self.repo.index.diff(remote_hash)]
        return updated_file

    def pull_from_remote(self):
        origin = self.repo.remotes.origin
        origin.pull()

    def get_local_repo_path(self):
        return str(self.local_repo_path)


__all__ = ["CvelistHandler"]
