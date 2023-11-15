import json
import pathutils

from CVEComponents import *
from nvdapi import CVEQuery

class CVEdb:
    pass


class CVE:
    def __init__(self, cve_metadata, containers, data_type = "CVE Record", data_version = "5.0", **kwargs) -> None:
        self.data_type = data_type
        self.data_version = data_version
        self.cve_metadata = cve_metadata
        self.containers = containers
        self.create_metrics()
        vars(self).update(kwargs)

        # print(vars(self.containers)["cna"]["metrics"])

    def __str__(self) -> str:
        return str(vars(self))

    def contains_metrics(self) -> bool:
        def check_metrics(container_type):
            return "metrics" in vars(self.containers)[container_type]

        if isinstance(self.containers, (CnaPublishedContainer, CnaRejectedContainer)):
            return check_metrics("cna")
        elif isinstance(self.containers, AdpContainer):
            return check_metrics("adp")

    def create_metrics(self) -> "Metrics":
        def create_metrics_helper(container_type):
            query = CVEQuery()
            if not "metrics" in vars(self.containers)[container_type]:
                nvd_info = query.get_cve_by_id(self.cve_metadata.cveId)
                return Metrics(True, **vars(nvd_info))
            else:
                return Metrics(**vars(self.containers)[container_type]["metrics"][0])

        metrics = None
        if isinstance(self.containers, (CnaPublishedContainer, CnaRejectedContainer)):
            metrics = create_metrics_helper("cna")
        elif isinstance(self.containers, AdpContainer):
            metrics = create_metrics_helper("adp")
        self.containers.add_metrics(metrics)


class CVEHandler:
    def __init__(self, db_path):
        self.db_path = pathutils.open_path(db_path)
        self.state = None
        self.cveMetadata = None
        self.containers = None

    def get_db_path(self):
        return self.db_path

    def parse_cve_json(self, json_path: str):
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

        cve = CVE(self.cveMetadata, self.containers)
        # print(vars(cve))
        return cve


__all__ = ["CVEHandler"]

