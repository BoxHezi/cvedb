import json
import argparse

from tinydb import TinyDB, Query
from tinydb.storages import JSONStorage
from tinydb.middlewares import CachingMiddleware

from cvetools.CVEComponents import *
from cvetools.CVEHandler import *
from cvetools.CVEListHandler import CvelistHandler

import pathutils

from pprint import pprint

# TODO: invoke create_metrics when required (cli argument)
# TODO: test performance of tinydb


def init_argparse() -> argparse.ArgumentParser:
    arg = argparse.ArgumentParser(description="CVE Local database in JSON format", formatter_class=argparse.RawTextHelpFormatter)
    arg.add_argument("-s", "--search", help="Search CVE(s) in local database\n", action="store_true")
    arg.add_argument("-y", "--year", help="Specify the year for querying/searching CVEs")
    # arg.add_argument("-p", "--pattern", help="Specific search pattern to search from local database") # TODO: add this for regex match
    arg.add_argument("--create-metrics", help="Ensure that metrics will be created\n"
                     "If there is no metrics in JSON file, query metrics information from NVD", action="store_true")
    arg.add_argument("--db", help="Specify path for local database\n"
                     "Default database path: $HOME/.config/cve/cvedb.json")
    return arg


class CVEdb:
    DEFAULT_DB_FILE = pathutils.DEFAULT_PROJECT_DIR / "cvedb.json"

    def __init__(self, db_path = DEFAULT_DB_FILE):
        storeage_path = str(db_path)
        self.db = TinyDB(storeage_path, storage=CachingMiddleware(JSONStorage))
        self.table = None

    def set_table(self, table):
        self.table = self.db.table(table)

    def insert(self, cve: CVE):
        year = cve.get_year()
        if not self.table or self.table.name != year:
            self.set_table(year)
        self.table.insert(jsonlialize_cve(cve))

    def upsert(self, cve, condition):
        # TODO: 1. insert cve if condition is False
        # TODO: 2. update cve if condition is True
        pass

    def query_by_id(self, cve_id):
        # TODO: implement query logic
        pass

    def close(self):
        self.db.close()


def jsonlialize_cve(data) -> dict:
    out = {}
    for k, v in vars(data).items():
        try:
            json.dumps(v)  # check if the value is json serializable
            out.update({k: v})
        except TypeError:
            out.update({k: jsonlialize_cve(v)})
    return out


def cvehandler_test():
    cvelist = CvelistHandler()
    print(f"CVE Local Database Path: {cvelist.get_local_repo_path()}")

    cvedb = CVEdb()
    cve_handler = CVEHandler(cvelist.get_local_repo_path())
    pattern = "**/CVE*.json" # TODO: modify pattern based on cli arguments
    for f in cve_handler.get_cvelist_path().glob(pattern):
    # for f in cve_handler.get_cvelist_path().glob("**/CVE-2013-3703.json"): # testing purpose, one JSON contains metrics
        # print(f)
        cve = cve_handler.create_cve_from_json(f)
        cvedb.insert(cve) # insert to database; TODO: insert to corresponding table based CVE year
        # print(vars(cve))
        # break
    cvedb.close()


def cvelistv5_test():
    cve_list = CvelistHandler()
    updated_file = cve_list.find_updated_files()
    print(updated_file)
    if len(updated_file) > 0:
        cve_list.pull_from_remote()


if __name__ == "__main__":
    # cvelistv5_test()
    cvehandler_test()
    # args = init_argparse().parse_args()
    # print(vars(args))

