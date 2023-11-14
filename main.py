import pathlib
import json
from typing import Optional

from pprint import pprint

from classes import *


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

    cve = CVE(metadata, containers)
    # print(vars(cve))
    return cve


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
    count = 0
    cve_path = pathlib.Path("./cvelistV5")
    # for f in cve_path.glob("**/CVE-2013-3703.json"):
    for f in cve_path.glob("**/CVE*.json"):
        # print(f)
        cve = None
        with open(f, "r") as file:
            data = json.load(file)
            cve = create_cve(data)

        if isinstance(cve.containers, (CnaPublishedContainer, CnaRejectedContainer)):
            if not "metrics" in vars(cve.containers)["cna"]:
                count += 1
        elif isinstance(cve.containers, AdpContainer):
            if not "metrics" in vars(cve.containers)["adp"]:
                count += 1
    print(count)

            # print(type(cve_to_json(cve)))
            # print(json.dumps(cve_to_json(cve), indent=4))

            # print(vars(cve))
            # print(type(vars(cve)))
            # print(type(cve))

            # print(vars(cve.cve_metadata))
            # print(vars(cve.containers))
            # print(json.dump(vars(cve), sys.stdout))
            # for k, v in vars(cve).items():
            #     print(k, v)

        # if isinstance(cve.containers, (CnaPublishedContainer, CnaRejectedContainer)):
        #     if "metrics" in vars(cve.containers)["cna"]:
        #         print(cve.cve_metadata.cveId)
        #         print(vars(cve.containers)["cna"]["metrics"])
        #         # break
        # elif isinstance(cve.containers, AdpContainer):
        #     if "metrics" in vars(cve.containers)["adp"]:
        #         print(cve.cve_metadata.cveId)
        #         print(vars(cve.containers)["adp"]["metrics"])
                # break
        # print(vars(cve.containers)["cna"]["metrics"])
        # break


if __name__ == "__main__":
    run()

