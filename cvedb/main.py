import argparse

from tqdm import tqdm

from .cvetools.CVEComponents import *
from .cvetools.CVEHandler import *
from .cvetools.CVEListHandler import CvelistHandler

from .cvedb import *
from . import pickleutils

from . import pathutils


def init_argparse() -> argparse.ArgumentParser:
    arg = argparse.ArgumentParser(description="CVE Local database in JSON format", formatter_class=argparse.RawTextHelpFormatter)
    data_group = arg.add_argument_group("CVE Database Arguments")
    data_group.add_argument("--repo", help="Clone github repo and parse CVE JSON files\n"
                     "If `--repo` is provided, other arguments will be ignored\n"
                     "If no exists local repo, git clone will be performed\n"
                     "Otherwise, it will check if there is any new updated file", action="store_true")

    search_group = arg.add_argument_group("Search CVE Arguments")
    search_group.add_argument("-s", "--search", help="Search CVE(s) in local database\n", action="store_true")

    arg.add_argument("-y", "--year", help="Specify the year for querying/searching CVEs")
    arg.add_argument("-i", "--id", help="Specify CVE id to search for")
    # arg.add_argument("-p", "--pattern", help="Specific search pattern to search from local database") # TODO: add this for regex match
    arg.add_argument("--create-metrics", help="Ensure that metrics will be created\n"
                     "If there is no metrics in JSON file, query metrics information from NVD", action="store_true")
    return arg


def clone_repo():
    cvelist = CvelistHandler()
    return cvelist


def handle_cve_json(cvelist: CvelistHandler, pattern: str = "**/CVE-*.json", files: list = None):
    # TODO: add pattern to cli arguments
    print(f"CVE Local Repo Path: {cvelist.get_local_repo_path()}")

    cvedb = CVEdb()
    cve_handler = CVEHandler(cvelist.get_local_repo_path())
    if files:
        for f in tqdm(files):
            abs_path = pathutils.DEFAULT_PROJECT_LOCAL_REPO / f
            cve = cve_handler.create_cve_from_json(abs_path)
            if cve.contains_metrics():
                cve.create_metrics(True)
            else:
                pass
            cvedb.upsert(cve)
    else:
        for f in tqdm(cve_handler.get_cvelist_path().glob(pattern)):
        # for f in cve_handler.get_cvelist_path().glob("**/CVE-2013-3703.json"): # testing purpose, one JSON contains metrics
            cve = cve_handler.create_cve_from_json(f)
            if cve.contains_metrics():
                cve.create_metrics(True)
            else:
                # TODO: call create_metrics when cli gives certain argument
                pass
            cvedb.upsert(cve)
            # break
    data = pickleutils.compress(pickleutils.serialize(cvedb))
    pickleutils.pickle_dump(cvedb.OUTPUT_PICKLE_FILE, data)


def main():
    args = init_argparse().parse_args()
    print(vars(args))

    if args.repo:  # first run, clone and create CVE from JSON files
        repo = clone_repo()
        if not repo.newly_clone:
            updated = repo.find_updated_files()
            print(len(updated))
            repo.pull_from_remote()
            handle_cve_json(repo, pattern=None, files=updated)
        else:
            handle_cve_json(repo)
        # handle_cve_json(repo)
    else:
        # TODO: load local database pickle file
        pass

if __name__ == "__main__":
    # cvelistv5_test()
    # cvehandler_test()
    # args = init_argparse().parse_args()
    # print(vars(args))

    # load from pickle test
    # data = pickle_load(CVEdb.OUTPUT_PICKLE_FILE)
    # cvedb = deserialize(decompress(data))
    # print(cvedb)
    main()