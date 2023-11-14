'''
Class definiations are defined based on the CVE JSON V5 Schema: https://github.com/CVEProject/cve-schema/blob/master/schema/v5.0/CVE_JSON_5.0_schema.json

CVE List V5 Github Repo: https://github.com/CVEProject/cvelistV5
'''

from nvdapi import CVEQuery

from pprint import pprint


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

    def create_metrics(self) -> "Metrics":
        def create_metrics_helper(container_type):
            if not "metrics" in vars(self.containers)[container_type]:
                nvd_info = query.get_cve_by_id(self.cve_metadata.cveId)
                return Metrics(True, **vars(nvd_info))
            else:
                return Metrics(**vars(self.containers)[container_type]["metrics"][0])

        query = CVEQuery()
        metrics = None
        if isinstance(self.containers, CnaContainer):
            metrics = create_metrics_helper("cna")
        elif isinstance(self.containers, AdpContainer):
            metrics = create_metrics_helper("adp")
        self.containers.add_metrics(metrics)


'''
CVE Metadata, contains two types:
    1. Published - Required fields: cveId, assignOrgId, state
    2. Rejected - Required fields: cveId, assignOrgId, state
'''
class CveMetadata:
    def __init__(self, **kwargs):
        vars(self).update(kwargs)

    def __str__(self) -> str:
        return str(vars(self))


class CveMetadataPublished(CveMetadata):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class CveMetadataRejected(CveMetadata):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


'''
Container, contains three types:
    1. CnaPublishedContainer - Required fields: providerMetadata, descriptions, affected, references
    2. CnaRejectedContainer - Required fields: providerMetadata, descriptions, affected, references
    3. AdpContainer - Required fields: providerMetadata
'''
class Container:
    def __init__(self, **kwargs):
        vars(self).update(kwargs)

    def __str__(self) -> str:
        return str(vars(self))


class CnaContainer(Container):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def add_metrics(self, metrics: "Metrics"):
        vars(self)["cna"].update({"metrics": metrics})


class CnaPublishedContainer(CnaContainer):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class CnaRejectedContainer(CnaContainer):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class AdpContainer(Container):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def add_metrics(self, metrics: "Metrics"):
        vars(self)["adp"].update({"metrics": metrics})


'''
Metrics
'''
class Metrics:
    def __init__(self, from_nvd: bool = False, **kwargs):
        if not from_nvd:
            if "cvssV3_1" in kwargs:
                vars(self).update(kwargs["cvssV3_1"])
            elif "cvssV3_0" in kwargs:
                vars(self).update(kwargs["cvssV3_0"])
            elif "cvssV2_0" in kwargs:
                vars(self).update(kwargs["cvssV2_0"])
        else:
            def process_metrics(metrics):
                del metrics[0].source
                del metrics[0].type
                vars(self).update(vars(metrics[0].cvssData))
                del metrics[0].cvssData
                vars(self).update(vars(metrics[0]))

            if "cvssMetricV31" in kwargs["metrics"]:
                process_metrics(kwargs["metrics"].cvssMetricV31)
            elif "cvssMetricV30" in kwargs["metrics"]:
                process_metrics(kwargs["metrics"].cvssMetricV30)
            elif "cvssMetricV2" in kwargs["metrics"]:
                process_metrics(kwargs["metrics"].cvssMetricV2)

    def __str__(self):
        return str(vars(self))



__all__ = ["CVE", "CveMetadataPublished", "CveMetadataRejected", "CnaPublishedContainer", "CnaRejectedContainer", "AdpContainer", "Metrics"]
