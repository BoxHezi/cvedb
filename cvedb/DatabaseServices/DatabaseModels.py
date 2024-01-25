from sqlalchemy import Column, Text, Integer, Float, Boolean, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

from datetime import datetime

DATETIME_FORMAT = "%Y-%m-%dT%H:%M:%S.%f"

Base = declarative_base()


class CVE(Base):
    __tablename__ = "cve"

    id = Column(Text, primary_key=True)
    status = Column(Text)
    source_identifier = Column(Text)
    published = Column(DateTime)
    last_modified = Column(DateTime)

    def __init__(self, **data):
        vars(self).update(data)
        self.status = vars(self)["vulnStatus"]
        self.source_identifier = vars(self)["sourceIdentifier"]
        self.published = datetime.strptime(vars(self)["published"], DATETIME_FORMAT)
        self.last_modified = datetime.strptime(vars(self)["lastModified"], DATETIME_FORMAT)

    def get_id(self):
        return self.id


class Description(Base):
    __tablename__ = "description"

    cve_id = Column(Text, ForeignKey("cve.id"), primary_key=True)
    language = Column(Text, primary_key=True)
    description = Column(Text)

    cve = relationship("CVE")

    def __init__(self, cve_id, **data):
        self.cve_id = cve_id
        vars(self).update(data)
        self.language = vars(self)["lang"]
        self.description = vars(self)["value"]


class Metrics(Base):
    __tablename__ = "metrics"

    cve_id = Column(Text, ForeignKey("cve.id"), primary_key=True)
    cvss_version = Column(Float, primary_key=True)
    source = Column(Text, primary_key=True)
    cvss_score = Column(Float, primary_key=True)
    severity = Column(Text)
    vector_string = Column(Text)
    confidentiality_impact = Column(Text)
    integrity_impact = Column(Text)
    availability_impact = Column(Text)

    cve = relationship("CVE")

    def __init__(self, cve_id, version, **data):
        self.cve_id = cve_id
        self.cvss_version = str(version)

        vars(self).update(data)

        if float(self.cvss_version) == 2.0:
            self.severity = vars(self)["baseSeverity"]
        else:
            self.severity = vars(self)["cvssData"]["baseSeverity"]

        self.cvss_score = vars(self)["cvssData"]["baseScore"]
        self.vector_string = vars(self)["cvssData"]["vectorString"]
        self.confidentiality_impact = vars(self)["cvssData"]["confidentialityImpact"]
        self.integrity_impact = vars(self)["cvssData"]["integrityImpact"]
        self.availability_impact = vars(self)["cvssData"]["availabilityImpact"]
        self.source = vars(self)["source"]



class Weakness(Base):
    __tablename__ = "weakness"

    cve_id = Column(Text, ForeignKey("cve.id"), primary_key=True)
    cwe_id = Column(Text, primary_key=True)
    source = Column(Text, primary_key=True)
    type = Column(Text)

    cve = relationship("CVE")

    def __init__(self, cve_id, **data):
        self.cve_id = cve_id
        vars(self).update(data)

        self.source = vars(self)["source"]
        self.cwe_id = vars(self)["description"][0]["value"]
        self.type = vars(self)["type"]


class AffectConfiguration(Base):
    __tablename__ = "affect_configuration"

    cve_id = Column(Text, ForeignKey("cve.id"), primary_key=True)
    configuration_id = Column(Integer, primary_key=True)
    match_criteria_id = Column(Text, primary_key=True)
    criteria = Column(Text)
    version_start_including = Column(Text)
    version_end_excluding = Column(Text)
    vulnerable = Column(Boolean)

    cve = relationship("CVE")

    def __init__(self, cve_id, configuration_id, **data):
        self.cve_id = cve_id
        self.configuration_id = configuration_id
        vars(self).update(data)

        self.match_criteria_id = vars(self)["matchCriteriaId"]
        self.criteria = vars(self)["criteria"]
        self.version_start_including = vars(self).get("versionStartIncluding", None)
        self.version_end_excluding = vars(self).get("versionEndExcluding", None)
        self.vulnerable = vars(self)["vulnerable"]

    def get_match_criterid_id(self):
        return self.match_criteria_id


class AffectConfigurationPartner(Base):
    __tablename__ = "affect_configuration_partner"

    cve_id = Column(Text, ForeignKey("affect_configuration.cve_id"), primary_key=True)
    configuration_id = Column(Integer, ForeignKey("affect_configuration.configuration_id"), primary_key=True)
    match_criteria_id = Column(Text, ForeignKey("affect_configuration.match_criteria_id"), primary_key=True)
    match_criteria_partner_id = Column(Text, primary_key=True)
    operator = Column(Text, default="AND")

    def __init__(self, cve_id, configuration_id, match_criteria_id, **data):
        self.cve_id = cve_id
        self.configuration_id = configuration_id
        self.match_criteria_id = match_criteria_id

        vars(self).update(data)
        self.match_criteria_partner_id = vars(self)["matchCriteriaId"]


class Reference(Base):
    __tablename__ = "reference"

    cve_id = Column(Text, ForeignKey("cve.id"), primary_key=True)
    reference_id = Column(Integer, primary_key=True)
    url = Column(Text)
    source = Column(Text)
    tags = Column(Text)

    cve = relationship("CVE")

    def __init__(self, cve_id, ref_id, **data):
        self.cve_id = cve_id
        self.reference_id = ref_id
        vars(self).update(data)

        self.url = vars(self)["url"]
        self.source = vars(self)["source"]
        self.tags = vars(self).get("tags", None)
        if self.tags:
            self.tags = ",".join(self.tags)




