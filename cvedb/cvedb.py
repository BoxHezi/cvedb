import json

from CVEComponents import *
from CVEHandler import *
from CVEListHandler import CvelistHandler


def cve_to_json(cve) -> dict:
    out = {}
    for k, v in vars(cve).items():
        try:
            json.dumps(v)  # check if the value is json serializable
            out.update({k: v})
        except TypeError:
            out.update({k: cve_to_json(v)})
    return out


def cvehandler_test():
    cvelist = CvelistHandler()
    print(f"CVE Local Database Path: {cvelist.get_local_repo_path()}")

    cve_handler = CVEHandler(cvelist.get_local_repo_path())
    pattern = "**/CVE*.json" # TODO: modify pattern based on cli arguments
    for f in cve_handler.get_cvelist_path().glob(pattern):
    # for f in cve_handler.get_db_path().glob("**/CVE-2013-3703.json"): # testing purpose, one JSON contains metrics
        # print(f)
        cve_handler.parse_cve_json(f)
        break


def cvelistv5_test():
    cve_list = CvelistHandler()
    updated_file = cve_list.find_updated_files()
    print(updated_file)
    if len(updated_file) > 0:
        cve_list.pull_from_remote()


if __name__ == "__main__":
    # cvelistv5_test()
    cvehandler_test()

