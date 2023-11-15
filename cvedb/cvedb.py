import pathlib
import json
from typing import Optional

from pprint import pprint

from CveClasses import *
from cvelistV5Handler import CvelistHandler

import pathutils


def create_cve_metadata(**metadata) -> Optional[CveMetadataPublished | CveMetadataRejected]:
    state = metadata["state"]
    if state == "PUBLISHED":
        return CveMetadataPublished(**metadata)
    elif state == "REJECTED":
        return CveMetadataRejected(**metadata)
    raise TypeError("Invalid CVE Metadata State")


def create_containers(metadata, **containers) -> Optional[CnaPublishedContainer | CnaRejectedContainer | AdpContainer]:
    if "cna" in containers:
        if metadata.state == "PUBLISHED":
            return CnaPublishedContainer(**containers)
        elif metadata.state == "REJECTED":
            return CnaRejectedContainer(**containers)
    elif "adp" in containers:
        return AdpContainer(**containers)
    else:
        raise TypeError("Invalid Containers Type")


def create_cve(data_json) -> CVE:
    try:
        metadata = create_cve_metadata(**data_json["cveMetadata"])
    except TypeError as e:
        raise e
    # print(type(metadata))
    # pprint(vars(metadata))

    try:
        containers = create_containers(metadata, **data_json["containers"])
    except TypeError as e:
        raise e
    # print(type(containers))
    # pprint(vars(containers))

    # print(vars(CVE(metadata, containers)))
    return CVE(metadata, containers)


def cve_to_json(cve) -> dict:
    out = {}
    for k, v in vars(cve).items():
        try:
            json.dumps(v)  # check if the value is json serializable
            out.update({k: v})
        except TypeError:
            out.update({k: cve_to_json(v)})
    return out


def run():
    cve_path = pathlib.Path("./cvelistV5")
    # for f in cve_path.glob("**/CVE-2013-3703.json"): # testing purpose, one JSON contains metrics
    for f in cve_path.glob("**/CVE*.json"):
        # print(f)
        cve = None
        with open(f, "r") as file:
            data = json.load(file)
            cve = create_cve(data)
        # break


class CVEdb:
    pass


class CVEHandler:
    def __init__(self, db_path):
        self.db_path = pathutils.open_path(db_path)

    def check_all(self):
        for f in self.db_path.glob("**/CVE*.json"):
            # print(f)
            cve = None
            with open(f, "r") as file:
                data = json.load(file)
            break


def cvehandler_test():
    cvelist = CvelistHandler()
    print(f"CVE Local Database Path: {cvelist.get_local_repo_path()}")
    cve_handler = CVEHandler(cvelist.get_local_repo_path())
    cve_handler.check_all()

def cvelistv5_test():
    cve_list = CvelistHandler()
    updated_file = cve_list.find_updated_files()
    print(updated_file)
    if len(updated_file) > 0:
        cve_list.pull_from_remote()


if __name__ == "__main__":
    # run()
    # cvelistv5_test()
    cvehandler_test()

