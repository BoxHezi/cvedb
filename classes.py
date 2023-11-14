'''
Class definiations are defined based on the CVE JSON V5 Schema: https://github.com/CVEProject/cve-schema/blob/master/schema/v5.0/CVE_JSON_5.0_schema.json

CVE List V5 Github Repo: https://github.com/CVEProject/cvelistV5
'''


class CVE:
    def __init__(self, cve_metadata, containers, data_type = "CVE Record", data_version = "5.0", **kwargs) -> None:
        self.data_type = data_type
        self.data_version = data_version
        self.cve_metadata = cve_metadata
        self.containers = containers
        vars(self).update(kwargs)

    def __str__(self) -> str:
        return str(vars(self))


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
        # TODO: query from NVD to get metrics data
        if not "metrics" in vars(self)["cna"]:
            # print("QUERY FROM NIST NVD")
            pass


class CnaPublishedContainer(CnaContainer):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class CnaRejectedContainer(CnaContainer):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)


class AdpContainer(Container):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # TODO: query from NVD to get metrics data
        if not "metrics" in vars(self)["adp"]:
            # print("QUERY FROM NIST NVD")
            pass


'''
Metrics
'''
class Metrics:
    def __init__(self, version, base_score, vector_string, **kwargs):
        self.version = version
        self.base_score = base_score
        self.vector_string = vector_string
        vars(self).update(kwargs)

    def get_severity(self):
        pass


__all__ = ["CVE", "CveMetadataPublished", "CveMetadataRejected", "CnaPublishedContainer", "CnaRejectedContainer", "AdpContainer", "Metrics"]
