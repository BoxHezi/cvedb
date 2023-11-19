import json

from cvetools.CVEComponents import *
from cvetools.CVEHandler import *
from cvetools.CVEListHandler import CvelistHandler

from pprint import pprint

# TODO: invoke create_metrics when required (cli argument)
# TODO: test performance of tinydb

# class CVEdb:
#     DEFAULT_DB_FILE = pathutils.DEFAULT_PROJECT_DIR / "cvedb.json"

#     def __init__(self, db_path = DEFAULT_DB_FILE):
#         storeage_path = str(db_path)
#         self.db = TinyDB(storeage_path, storage=CachingMiddleware(JSONStorage))
#         self.table = None

#     def set_table(self, table):
#         self.table = self.db.table(table)

#     def insert(self, cve: CVE):
#         year = cve.get_year()
#         if not self.table or self.table.name != year:
#             self.set_table(year)
#         self.table.insert(jsonlialize_cve(cve))

#     def upsert(self, cve, condition):
#         # TODO: 1. insert cve if condition is False
#         # TODO: 2. update cve if condition is True
#         pass

#     def query_by_id(self, cve_id):
#         # TODO: implement query logic
#         pass

#     def close(self):
#         self.db.close()


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
    def __init__(self):
        self.table_count = 0
        self.total_data_count = 0
        self.records: dict[int, Table] = {} # key-value pair, where key is table name, value is table

    def update_stat(self):
        self.table_count = len(self.records.keys())
        count = 0
        for _, v in self.records.items():
            count += v.data_count
        self.total_data_count = count

    def stat(self):
        for k, v in self.records.items():
            print(f"{k}: {v.data_count}")

        print(f"Table Count: {self.table_count}")
        print(f"Total Data Count: {self.total_data_count}")

    def insert(self, data: CVE):
        year = data.get_year()
        if year not in self.records:
            self.records[year] = Table(year)
        table = self.records[year]
        table.insert(data)

    def search_by_id(self, cve_id):
        year = int(cve_id.split("-")[1])
        table = self.records[year]
        return table.search_by_id(cve_id)


class Table:
    def __init__(self, table_name):
        self.table_name = table_name
        self.data_count = 0
        self.data = {}

    def insert(self, data: CVE):
        if data.get_cve_id() in self.data:
            raise KeyError("Duplicate CVE ID found in database")
        self.data.update({data.get_cve_id(): data})
        self.data_count += 1

    # def upsert(self, data: CVE):
    #     if not data.get_cve_id() in self.data:
    #         self.data_count += 1
    #     self.data.update({data.get_cve_id(): data})

    # def delete(self, data: CVE):
    #     if not data.get_cve_id() in self.data:
    #         raise KeyError("CVE ID not exists")
    #     del self.data[data.get_cve_id()]

    def search_by_id(self, cve_id):
        if not cve_id in self.data:
            raise KeyError("CVE not found")
        return self.data[cve_id]


def jsonlialize_cve(data) -> dict:
    out = {}
    for k, v in vars(data).items():
        try:
            json.dumps(v)  # check if the value is json serializable
            out.update({k: v})
        except TypeError:
            out.update({k: jsonlialize_cve(v)})
    return out


def cvelistv5_test():
    cve_list = CvelistHandler()
    updated_file = cve_list.find_updated_files()
    print(updated_file)
    if len(updated_file) > 0:
        cve_list.pull_from_remote()


# if __name__ == "__main__":
#     # cvelistv5_test()
#     cvehandler_test()
#     # args = init_argparse().parse_args()
#     # print(vars(args))

__all__ = ["CVEdb"]

