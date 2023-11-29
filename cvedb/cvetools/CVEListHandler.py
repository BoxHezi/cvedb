import git

from ..utils import pathutils

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
    """
    Class to handle cvelistV5 repo
    """
    def __init__(self):
        pathutils.create_path(pathutils.DEFAULT_PROJECT_DIR)
        self.local_repo_path = pathutils.DEFAULT_PROJECT_DIR / "cvelistV5"

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

        updated_file = []
        for file in self.repo.index.diff(remote_hash):
            if "delta" in file.a_path:  # ignore delta.json and deltaLog.json
                continue
            updated_file.append(file.a_path)
        return updated_file

    def pull_from_remote(self):
        origin = self.repo.remotes.origin
        origin.pull()

    def get_local_repo_path(self):
        return str(self.local_repo_path)


__all__ = ["CvelistHandler"]
