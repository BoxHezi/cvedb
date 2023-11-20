import argparse
import pickle

from tqdm import tqdm

from cvetools.CVEComponents import *
from cvetools.CVEHandler import *
from cvetools.CVEListHandler import CvelistHandler

from cvedb import *


def init_argparse() -> argparse.ArgumentParser:
    arg = argparse.ArgumentParser(description="CVE Local database in JSON format", formatter_class=argparse.RawTextHelpFormatter)
    arg.add_argument("--init", help="Clone github repo and parse CVE JSON files")
    arg.add_argument("-s", "--search", help="Search CVE(s) in local database\n", action="store_true")
    arg.add_argument("-y", "--year", help="Specify the year for querying/searching CVEs")
    arg.add_argument("-i", "--id", help="Specify CVE id to search for")
    # arg.add_argument("-p", "--pattern", help="Specific search pattern to search from local database") # TODO: add this for regex match
    arg.add_argument("--create-metrics", help="Ensure that metrics will be created\n"
                     "If there is no metrics in JSON file, query metrics information from NVD", action="store_true")
    # arg.add_argument("--db", help="Specify path for local database\n"
    #                  "Default database path: $HOME/.config/cve/cvedb.json")
    return arg


def pickle_dump(path, obj):
    with open(path, "wb") as file:
        pickle.dump(obj, file)


def pickle_load(path):
    with open(path, "rb") as file:
        return pickle.load(file)


def cvehandler_test():
    cvelist = CvelistHandler()
    print(f"CVE Local Repo Path: {cvelist.get_local_repo_path()}")

    cvedb = CVEdb()

    cve_handler = CVEHandler(cvelist.get_local_repo_path())
    pattern = "**/CVE-*.json" # TODO: modify pattern based on cli arguments
    for f in tqdm(cve_handler.get_cvelist_path().glob(pattern)):
    # for f in cve_handler.get_cvelist_path().glob("**/CVE-2013-3703.json"): # testing purpose, one JSON contains metrics
        # print(f)
        cve = cve_handler.create_cve_from_json(f)
        cvedb.insert(cve)
        # print(vars(cve))
        # break
    # print(vars(cvedb))
    # cvedb.update_stat()
    # print(cvedb.stat())
    # cvedb.close()
    # print(cvedb.search_by_id("CVE-2013-3703"))
    pickle_dump(cvedb.OUTPUT_PICKLE_FILE, cvedb)


if __name__ == "__main__":
    # cvelistv5_test()
    cvehandler_test()
    # args = init_argparse().parse_args()
    # print(vars(args))

    # load from pickle test
    # cvedb = pickle_load(CVEdb.OUTPUT_PICKLE_FILE)
    # print(type(cvedb))
    # print(cvedb)