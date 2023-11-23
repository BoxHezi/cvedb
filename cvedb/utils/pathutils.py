import pathlib


DEFAULT_PROJECT_DIR = pathlib.Path.home() / ".config/cvedb"
DEFAULT_PROJECT_LOCAL_REPO = DEFAULT_PROJECT_DIR / "cvelistV5"

# def home_dir():
#     return pathlib.Path.home()


def create_path(path: str, parents=True, exist_ok=True):
    try:
        p = pathlib.Path(path)
        p.mkdir(mode=0o744, parents=parents, exist_ok=exist_ok)
    except Exception:
        print(f"Exception when creating director {path}")


def path_exists(path: str):
    p = pathlib.Path(path)
    return p.exists()


def open_path(path: str) -> pathlib.Path:
    return pathlib.Path(path)


