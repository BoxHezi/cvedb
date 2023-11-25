from tqdm import tqdm

from .cvetools.CVEComponents import *
from .cvetools.CVEHandler import *
from .cvetools.CVEListHandler import CvelistHandler

from .cvedb import *
from .utils import pickleutils
from .utils import pathutils
from .utils import argsutils
from .utils import regexutils

from .version import __version__

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


DEFAULT_PATTERN = "**/CVE-*.json"


class CVEdb:
    OUTPUT_PICKLE_FILE = pathutils.DEFAULT_PROJECT_DIR / "cvedb.pickle"

    def __init__(self):
        self.table_count = 0
        self.total_data_count = 0
        self.records: dict[int, Table] = {} # key-value pair, where key is table name, value is table

    # TODO: add implementation to track total_data_count
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


def dump_db(cvedb: CVEdb, out_path: str = CVEdb.OUTPUT_PICKLE_FILE):
    print(f"Store cvedb to {out_path}")
    data = pickleutils.compress(pickleutils.serialize(cvedb))
    pickleutils.pickle_dump(out_path, data)


def load_db(db_path = CVEdb.OUTPUT_PICKLE_FILE) -> CVEdb:
    cvedb = pickleutils.pickle_load(db_path)
    cvedb = pickleutils.deserialize(pickleutils.decompress(cvedb))
    print(type(cvedb))
    return cvedb


def create_db() -> CVEdb:
    """
    create new CVEdb instance
    """
    return CVEdb()


def init_cvedb(db_path = CVEdb.OUTPUT_PICKLE_FILE):
    """
    Initialize cve database. Load local pickle file; if no local database find, create a new CVEdb instance
    """
    try:
        print(f"Loading cve database from {db_path}")
        return load_db(db_path)
    except:
        print(f"No local database found in path {db_path}, creating new CVEdb")
        return create_db()


def process_file(file, create_metrics: bool, cve_handler: CVEHandler) -> CVE:
    cve = cve_handler.create_cve_from_json(file)
    if cve.contains_metrics():
        cve.create_metrics(True)  # create Metrics if CVE JSON file contains metrics entry
    else:
        create_metrics and cve.create_metrics(False)
        # if create_metrics:
        #     cve.create_metrics(False)
    return cve


def handle_updated_cve(cvelist: CvelistHandler, files: list = [], args = None):
    cvedb = init_cvedb()
    cve_handler = CVEHandler(cvelist.get_local_repo_path())
    for f in tqdm(files):
        path = pathutils.DEFAULT_PROJECT_LOCAL_REPO / f
        cve = process_file(path, args.create_metrics, cve_handler)
        cvedb.upsert(cve)
    dump_db(cvedb)


def handle_cve_json(cvelist: CvelistHandler, pattern: str = DEFAULT_PATTERN, args = None):
    cvedb = init_cvedb()
    cve_handler = CVEHandler(cvelist.get_local_repo_path())
    for f in tqdm(cve_handler.get_cvelist_path().glob(pattern)):
    # for f in cve_handler.get_cvelist_path().glob("**/CVE-2013-3703.json"): # testing purpose, one JSON contains metrics
        cve = process_file(f, args.create_metrics, cve_handler)
        cvedb.upsert(cve)
    dump_db(cvedb)


def clone_or_update(args):
    if args.clone and args.update:
        raise Exception("Invalid arguments combination")
    repo = CvelistHandler()
    if args.clone:
        handle_cve_json(repo, args=args)
    elif args.update:
        updated = repo.find_updated_files()
        repo.pull_from_remote()
        handle_updated_cve(repo, files=updated, args=args)


def search(cvedb: CVEdb, year: int, id: str, pattern: str) -> dict | CVE:
    # TODO: add pattern match for searching logic
    if year:
        return cvedb.get_cves_by_year(year)
    elif id:
        return cvedb.get_cve_by_id(id)


def main():
    args = argsutils.init_argparse().parse_args()
    # print(vars(args))
    if args.version:
        print(f"CVEdb - {__version__}")
    elif args.clone or args.update:
        clone_or_update(args)
    elif args.search:
        # TODO: search functions
        cvedb = init_cvedb()
        data = search(cvedb, args.year, args.id, None)
        return data
        # for k, v in vars(record).items():
        #     try:
        #         print(k, vars(v))
        #     except:
        #         print(k, v)


if __name__ == "__main__":
    # cvelistv5_test()
    # cvehandler_test()
    # args = init_argparse().parse_args()
    # print(vars(args))

    # load from pickle test
    # cvedb = load_or_create_cvedb()
    main()


# __all__ = ["CVEdb"]

