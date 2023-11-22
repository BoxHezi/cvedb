import argparse

from tqdm import tqdm

from .cvetools.CVEComponents import *
from .cvetools.CVEHandler import *
from .cvetools.CVEListHandler import CvelistHandler

from .cvedb import *
from . import pickleutils

from . import pathutils


def init_argparse() -> argparse.ArgumentParser:
    arg = argparse.ArgumentParser(description="CVE Local database in JSON format", formatter_class=argparse.RawTextHelpFormatter)
    db_group = arg.add_argument_group("CVE Database Arguments")
    db_group.add_argument("--clone", help="Clone Github cvelistV5 repo", action="store_true")
    db_group.add_argument("--update", help="Check if there is any update from remote repo", action="store_true")
    db_group.add_argument("--create-metrics", help="Ensure that metrics will be created\n"
                     "If there is no metrics in JSON file, query metrics information from NVD", action="store_true")

    search_group = arg.add_argument_group("Search CVE Arguments")
    search_group.add_argument("-s", "--search", help="Search CVE(s) in local database\n", action="store_true")
    search_group.add_argument("-o", "--out", help="Specify output path, JSON format supported.")

    arg.add_argument("-y", "--year", help="Specify the year for querying/searching CVEs")
    arg.add_argument("-i", "--id", help="Specify CVE id to search for")
    # arg.add_argument("-p", "--pattern", help="Specific search pattern to search from local database") # TODO: add this for regex match
    return arg


def dump_cvedb(cvedb: CVEdb, out_path: str = CVEdb.OUTPUT_PICKLE_FILE):
    print(f"Store cvedb to {out_path}")
    data = pickleutils.compress(pickleutils.serialize(cvedb))
    pickleutils.pickle_dump(out_path, data)


def load_cvedb(db_path = CVEdb.OUTPUT_PICKLE_FILE) -> CVEdb:
    cvedb = pickleutils.pickle_load(db_path)
    cvedb = pickleutils.deserialize(pickleutils.decompress(cvedb))
    return cvedb


def create_cvedb() -> CVEdb:
    return CVEdb()


def init_cvedb(db_path = CVEdb.OUTPUT_PICKLE_FILE):
    """
    Initialize cve database. Load local pickle file; if no local database find, create a new CVEdb instance
    """
    try:
        print(f"Loading cve database from {db_path}")
        return load_cvedb(db_path)
    except:
        print(f"No local database found in path {db_path}, creating new CVEdb")
        return create_cvedb()


def pattern_from_year_or_id(args: argparse.Namespace) -> str:
    """
    Generate pattern from year or id given by CLI argument
    If no year or id is provide, return the default pattern match for all CVE json files
    """
    if args.year and args.id:
        raise Exception("Invalid arguments combination, year and id")
    if args.year:
        return f"**/CVE-{args.year}*.json"
    elif args.id:
        return args.id
    return "**/CVE-*.json"


def process_file(file, create_metrics: bool, cve_handler: CVEHandler) -> CVE:
    cve = cve_handler.create_cve_from_json(file)
    if cve.contains_metrics():
        cve.create_metrics(True)
    else:
        if create_metrics:
            cve.create_metrics(False)
    return cve


def handle_updated_cve(cvelist: CvelistHandler, files: list = [], args: argparse.Namespace = None):
    cvedb = init_cvedb()
    cve_handler = CVEHandler(cvelist.get_local_repo_path())
    for f in tqdm(files):
        path = pathutils.DEFAULT_PROJECT_LOCAL_REPO / f
        cve = process_file(path, args.create_metrics, cve_handler)
        cvedb.upsert(cve)
    dump_cvedb(cvedb)


def handle_cve_json(cvelist: CvelistHandler, pattern: str = "**/CVE-*.json", args: argparse.Namespace = None):
    cvedb = init_cvedb()
    cve_handler = CVEHandler(cvelist.get_local_repo_path())
    for f in tqdm(cve_handler.get_cvelist_path().glob(pattern)):
    # for f in cve_handler.get_cvelist_path().glob("**/CVE-2013-3703.json"): # testing purpose, one JSON contains metrics
        cve = process_file(f, args.create_metrics, cve_handler)
        cvedb.upsert(cve)
    dump_cvedb(cvedb)


def clone_or_update(args: argparse.Namespace):
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
    if year:
        return cvedb.get_cves_by_year(year)
    elif id:
        return cvedb.get_cve_by_id(id)


def main():
    args = init_argparse().parse_args()
    # print(vars(args))

    if args.clone or args.update:
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