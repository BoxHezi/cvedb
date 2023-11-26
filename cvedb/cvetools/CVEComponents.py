'''
Class definiations are defined based on the CVE JSON V5 Schema: https://github.com/CVEProject/cve-schema/blob/master/schema/v5.0/CVE_JSON_5.0_schema.json

CVE List V5 Github Repo: https://github.com/CVEProject/cvelistV5
'''


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

    def add_metrics(self, container_type, metrics: "Metrics"):
        # vars(self)[container_type].update({"metrics": vars(metrics)})
        # vars(self)[container_type]["metrics"] = vars(metrics)
        vars(self)[container_type].update({"metrics": metrics})

    def get_metrics(self, container_type):
        return vars(self)[container_type]["metrics"]

    def get_container_type(self):
        if isinstance(self, CnaContainer):
            return "cna"
        elif isinstance(self, AdpContainer):
            return "adp"
        else:
            None


class CnaContainer(Container):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def add_metrics(self, metrics: "Metrics"):
        super().add_metrics("cna", metrics)


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
        super().add_metrics("adp", metrics)


'''
Metrics
'''
class Metrics(dict):
    def __init__(self, from_nvd: bool = False, **kwargs):
        if not from_nvd:
            self.process_metrics_from_json(**kwargs)
        else:
            self.process_metrics_from_nvd(**kwargs)
        dict.__init__(self, vars(self))

    def process_metrics_from_json(self, **kwargs):
        if "cvssV3_1" in kwargs:
            vars(self).update(kwargs["cvssV3_1"])
        elif "cvssV3_0" in kwargs:
            vars(self).update(kwargs["cvssV3_0"])
        elif "cvssV2_0" in kwargs:
            vars(self).update(kwargs["cvssV2_0"])

    def process_metrics_from_nvd(self, **kwargs):
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



__all__ = ["CveMetadataPublished", "CveMetadataRejected", "CnaPublishedContainer", "CnaRejectedContainer", "AdpContainer", "Metrics"]
