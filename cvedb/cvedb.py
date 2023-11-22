from .cvetools.CVEComponents import *
from .cvetools.CVEHandler import *
from . import pathutils


"""
CVEdb contains Table
Table contains CVEs
table_name is the year of individual CVE

example format can be described as:
{
    '2023': {
        'CVE-2023-0001': {},
        'CVE-2023-0002': {}
    },
    '2022': {
        'CVE-2022-0001': {},
        'CVE-2022-0002': {}
    }
}
"""

class CVEdb:
    OUTPUT_PICKLE_FILE = pathutils.DEFAULT_PROJECT_DIR / "cvedb.pickle"

    def __init__(self):
        self.table_count = 0
        self.total_data_count = 0
        self.records: dict[int, Table] = {} # key-value pair, where key is table name, value is table

    # def update_stat(self):
    #     self.table_count = len(self.records.keys())
    #     count = 0
    #     for _, v in self.records.items():
    #         count += v.data_count
    #     self.total_data_count = count

    # def stat(self):
    #     for k, v in self.records.items():
    #         print(f"{k}: {v.data_count}")

    #     print(f"Table Count: {self.table_count}")
    #     print(f"Total Data Count: {self.total_data_count}")

    def upsert(self, data: CVE):
        year = data.get_cve_year()
        if year not in self.records:
            self.records[year] = Table(year)
        table = self.records[year]
        table.upsert(data)

    def retrieve_records_by_year(self, year: int):
        try:
            return self.records[int(year)]
        except:
            raise KeyError("Invalid year")

    def get_cve_by_id(self, cve_id) -> CVE:
        year = int(cve_id.split("-")[1])
        table = self.records[year]
        return table.get_by_id(cve_id)

    def get_cves_by_year(self, year) -> dict:
        table = self.records[int(year)]
        return table.get_data()


class Table:
    def __init__(self, table_name):
        self.table_name = table_name
        self.data_count = 0
        self.data = {}

    def upsert(self, data: CVE):
        if not data.get_cve_id() in self.data:
            self.data_count += 1
        self.data.update({data.get_cve_id(): data})

    def get_by_id(self, cve_id) -> CVE:
        if not cve_id in self.data:
            raise KeyError("CVE not found")
        return self.data[cve_id]

    def get_data(self):
        return self.data


# def jsonlialize_cve(data) -> dict:
#     out = {}
#     for k, v in vars(data).items():
#         try:
#             json.dumps(v)  # check if the value is json serializable
#             out.update({k: v})
#         except TypeError:
#             out.update({k: jsonlialize_cve(v)})
#     return out


__all__ = ["CVEdb"]

