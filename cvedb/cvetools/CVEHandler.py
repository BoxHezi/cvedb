import json
import pathutils

from cvetools.CVEComponents import *
from nvdapi import CVEQuery


class CVE:
    def __init__(self, metadata, containers, data_type = "CVE Record", data_version = "5.0", **kwargs) -> None:
        self.data_type = data_type
        self.data_version = data_version
        self.metadata = metadata
        self.containers = containers
        # print(self.containers.get_container_type())
        # print(f"JSON Contains metrics: {self.contains_metrics()}")
        self.create_metrics()
        vars(self).update(kwargs)

        # print(vars(self.containers)["cna"]["metrics"])

    def __str__(self) -> str:
        return str(vars(self))

    def contains_metrics(self) -> bool:
        def check_metrics(container_type):
            return "metrics" in vars(self.containers)[container_type]

        return check_metrics(self.containers.get_container_type())
        # can be done in one line, but keep helper function `check_metrics()` for better readability
        # return "metrics" in vars(self.containers)[self.containers.get_container_type()]

    def create_metrics(self) -> "Metrics":
        def create_metrics_helper(container_type):
            if not "metrics" in vars(self.containers)[container_type]:
                nvd_info = CVEQuery().get_cve_by_id(self.metadata.cveId)
                return Metrics(True, **vars(nvd_info))
            else:
                return Metrics(**vars(self.containers)[container_type]["metrics"][0])

        self.containers.add_metrics(create_metrics_helper(self.containers.get_container_type()))


class CVEHandler:
    def __init__(self, cvelist_path):
        self.cvelist_path = pathutils.open_path(cvelist_path)
        self.state = None
        self.cveMetadata = None
        self.containers = None

    def get_cvelist_path(self):
        return self.cvelist_path

    def create_cve_from_json(self, json_path: str):
        with open(json_path, "r") as file:
            data = json.load(file)
            try:
                return self.create_cve(data)
            except:
                raise Exception(f"Exception when creating CVE instance on file: {json_path}")

    def parse_cve_metadata(self, **metadata):
        self.state = metadata["state"]
        if self.state == "PUBLISHED":
            self.cveMetadata = CveMetadataPublished(**metadata)
        elif self.state == "REJECTED":
            self.cveMetadata = CveMetadataRejected(**metadata)
        else:
            raise TypeError("Invalid CVE Metadata State")

    def parse_containers(self, **containers):
        if "cna" in containers:
            if self.state == "PUBLISHED":
                self.containers = CnaPublishedContainer(**containers)
            elif self.state == "REJECTED":
                self.containers = CnaRejectedContainer(**containers)
            else:
                raise TypeError("Invalid CVE Metadata State")
        elif "adp" in containers:
            self.containers = AdpContainer(**containers)
        else:
            raise TypeError("Invalid Containers Type")

    def create_cve(self, data) -> CVE:
        try:
            self.parse_cve_metadata(**data["cveMetadata"])
            self.parse_containers(**data["containers"])
        except Exception as e:
            raise e

        # print(self.cveMetadata)
        # print(self.containers)
        cve = CVE(self.cveMetadata, self.containers)
        # print(cve)
        # print(vars(cve.containers)["cna"]["metrics"])
        # print(vars(cve))
        return cve


__all__ = ["CVEHandler", "CVE"]

