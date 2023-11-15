import os

import nvdlib

KEY = os.getenv("NVD_KEY")

class CVEQuery:
    def __init__(self, key=KEY):
        self.key = key

    def get_cve_by_id(self, cve_id):
        cve = list(nvdlib.searchCVE_V2(cveId=cve_id, key=self.key, delay=1 if self.key else None))[0]
        return cve

