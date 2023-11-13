'''
Class definiations are defined based on the CVE JSON V5 Schema: https://github.com/CVEProject/cve-schema/blob/master/schema/v5.0/CVE_JSON_5.0_schema.json
'''


class CVE:
    def __init__(self, cve_metadata, containers, data_type = "CVE Record", data_version = "5.0", **kwargs) -> None:
        self.data_type = data_type
        self.data_version = data_version
        self.cve_metadata = cve_metadata
        self.container = containers
        vars(self).update(kwargs)

'''
CVE Metadata, contains two types:
    1. Published
    2. Rejected
'''
class Cve_Metadata:
    def __init__(self, cve_id, assigner_org_id,  **kwargs):
        self.cve_id = cve_id
        self.assigner_org_id = assigner_org_id
        vars(self).update(kwargs)


class Cve_Metadata_Published(Cve_Metadata):
    def __init__(self, cve_id, assigner_org_id, state = "Published", **kwargs):
        super().__init__(cve_id, assigner_org_id, kwargs)
        self.state = state


class Cve_Metadata_Rejected(Cve_Metadata):
    def __init__(self, cve_id, assigner_org_id, state = "Rejected", **kwargs):
        super().__init__(cve_id, assigner_org_id, kwargs)
        self.state = state


'''
Container, contains three types:
    1. CnaPublishedContainer
    2. CnaRejectedContainer
    3. AdpContainer
'''
class Container:
    def __init__(self, provider_metadata, **kwargs):
        self.provider_metadata = provider_metadata
        vars(self).update(kwargs)


class CnaContainer(Container):
    def __init__(self, provider_metadata, descriptions, affected, references, **kwargs):
        super().__init__(provider_metadata, **kwargs)
        self.descriptions = descriptions
        self.affected = affected
        self.references = references


class CnaPublishedContainer(CnaContainer):
    def __init__(self, provider_metadata, descriptions, affected, references, **kwargs):
        super().__init__(provider_metadata, descriptions, affected, references, **kwargs)


class CnaRejectedContainer(CnaContainer):
    def __init__(self, provider_metadata, descriptions, affected, references, **kwargs):
        super().__init__(provider_metadata, descriptions, affected, references, **kwargs)

class AdpContainer(Container):
    def __init__(self, provider_metadata, **kwargs):
        super().__init__(provider_metadata, **kwargs)


'''
Metrics
'''
class Metrics:
    def __init__(self, version, base_score, vector_string, **kwargs):
        self.version = version
        self.base_score = base_score
        self.vector_string = vector_string
        vars(self).update(kwargs)
