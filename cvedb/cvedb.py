import re
import json
from tqdm import tqdm

from .cvetools.CVEComponents import *
from .cvetools.CVEHandler import *
from .cvetools.CVEListHandler import CvelistHandler

from .cvedb import *
from .utils import pickleutils
from .utils import pathutils
from .utils import argsutils

from .version import __version__

"""
CVEdb contains Table
Table contains CVEs
table_name is the year of individual CVE

example format can be described as:
{
    '2023': {
        'table_name': "2023",
        'data_count': 2
        'CVE-2023-0001': {},
        'CVE-2023-0002': {}
    },
    '2022': {
        'table_name': "2022",
        'data_count': 2
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

    def update_stat(self):
        """
        Updates the statistics of the CVEdb object.

        This function calculates and updates the number of tables (or records) and the total data count across all tables.
        The `table_count` is the number of keys in the `records` dictionary.
        The `total_data_count` is calculated by iterating over all tables in `records` and summing up their `data_count` values.

        :return: A tuple containing the table count and the total data count.
        """
        self.table_count = len(self.records.keys())
        count = 0
        for _, v in self.records.items():
            count += v.data_count
        self.total_data_count = count
        return self.table_count, self.total_data_count

    def upsert(self, data: CVE):
        year = data.get_cve_year()
        if year not in self.records:
            self.records[year] = Table(year, 0, {})
        table = self.records[year]
        table.upsert(data)

    def get_cve_by_id(self, cve_id) -> CVE:
        year = int(cve_id.split("-")[1])
        table = self.records[year]
        return table.get_by_id(cve_id)

    def get_cves_by_year(self, year, pattern = None):
        """
        Retrieves all CVEs for a given year that match a certain pattern and returns them in a new Table instance.

        :param year: The year to select the table of CVEs.
        :param pattern: The pattern to filter the CVEs. This is optional.
        :return: A new Table instance containing the CVEs for the given year that match the pattern.
        """
        pattern = argsutils.process_pattern(pattern) if pattern else r"()" # convert cli pattern to regex
        # print(f"Pattern: {pattern}")
        table = self.records[int(year)]
        out = {"table_name": table.table_name, "data_count": 0, "data": {}}
        for k, v in table.data.items():  # k: str, cveid; v: CVE instance
            cve_json = jsonlialize_cve(v)
            if re.match(pattern, str(cve_json)):
                out["data"].update({k: cve_json})
                out["data_count"] = out["data_count"] + 1

        out_table = Table(out["table_name"], out["data_count"], out["data"])  # create a new Table instance
        return out_table

    def __str__(self) -> str:
        self.update_stat()
        return f"Table Count: {self.table_count}\nTotal Data Count: {self.total_data_count}"


class Table:
    def __init__(self, table_name, data_count: int, data: dict[str, CVE]):
        self.table_name = table_name
        self.data_count = data_count
        self.data: dict[str, CVE] = data

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

    def __str__(self):
        return f"Table: {self.table_name}\nData Count: {self.data_count}"


def jsonlialize_cve(data) -> dict:
    out = {}
    for k, v in vars(data).items():
        try:
            json.dumps(v)  # check if the value is json serializable
            out.update({k: v})
        except TypeError:
            out.update({k: jsonlialize_cve(v)})
    return out


def dump_db(cvedb: CVEdb, out_path: str = CVEdb.OUTPUT_PICKLE_FILE):
    """
    Serialize and store the `cvedb` object into a file.

    :param cvedb: The CVEdb object to be stored.
    :param out_path: The path where the serialized object will be stored. Defaults to CVEdb.OUTPUT_PICKLE_FILE.
    """
    print(f"Store cvedb to {out_path}")
    data = pickleutils.compress(pickleutils.serialize(cvedb))
    pickleutils.pickle_dump(out_path, data)


def init_db(db_path = CVEdb.OUTPUT_PICKLE_FILE):
    """
    Initialize a CVE (Common Vulnerabilities and Exposures) database.

    This function tries to load a CVEdb object from a local pickle file. If it cannot find the file or if there is an error during loading, it creates a new CVEdb instance.

    :param db_path: The path where the serialized object is stored. Defaults to CVEdb.OUTPUT_PICKLE_FILE.
    :return: The deserialized CVEdb object or a new CVEdb instance if the file does not exist or there is an error during loading.
    :raises Exception: If there is an error during loading, decompression, or deserialization.
    """
    try:
        print(f"Loading cve database from {db_path}")
        cvedb = pickleutils.pickle_load(db_path)
        cvedb = pickleutils.deserialize(pickleutils.decompress(cvedb))
        return cvedb
    except:
        print(f"No local database found in path {db_path}, creating new CVEdb")
        return CVEdb()


def process_file(file, cve_handler: CVEHandler, create_metrics: bool) -> CVE:
    cve = cve_handler.create_cve_from_json(file)
    if cve.contains_metrics():
        cve.create_metrics(True)  # create Metrics if CVE JSON file contains metrics entry
    else:
        create_metrics and cve.create_metrics(False)
    return cve


def handle_updated_cve(cvedb: CVEdb, local_repo_path: str, files: list, args = None):
    cve_handler = CVEHandler(local_repo_path)
    for f in tqdm(files):
        path = pathutils.DEFAULT_PROJECT_LOCAL_REPO / f
        cve = process_file(path, cve_handler, args.create_metrics)
        cvedb.upsert(cve)


def handle_cve_json(cvedb: CVEdb, local_repo_path: str, pattern: str = DEFAULT_PATTERN, args = None):
    cve_handler = CVEHandler(local_repo_path)
    for f in tqdm(cve_handler.get_cvelist_path().glob(pattern)):
    # for f in cve_handler.get_cvelist_path().glob("**/CVE-2013-3703.json"): # testing purpose, one JSON contains metrics
        cve = process_file(f, cve_handler, args.create_metrics)
        cvedb.upsert(cve)


def clone_or_update(args):
    if args.clone and args.update:
        raise Exception("Invalid arguments combination")
    repo = CvelistHandler()
    cvedb = init_db()
    if args.clone:
        handle_cve_json(cvedb, repo.get_local_repo_path(), args=args)
    elif args.update:
        updated = repo.find_updated_files()
        repo.pull_from_remote()
        handle_updated_cve(cvedb, repo.get_local_repo_path(), files=updated, args=args)
    dump_db(cvedb)


def search(cvedb: CVEdb, year: int, id: str, pattern: str) -> dict | CVE:
    if year:
        return cvedb.get_cves_by_year(year, pattern)
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
        cvedb = init_db()
        data = search(cvedb, args.year, args.id, args.pattern)
        # print(json.dumps(jsonlialize_cve(data), indent=2))
        # print(type(data))
        return data


if __name__ == "__main__":
    main()


# __all__ = ["CVEdb"]

