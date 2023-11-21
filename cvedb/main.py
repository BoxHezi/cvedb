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
    data_group = arg.add_argument_group("CVE Database Arguments")
    data_group.add_argument("--clone", help="Clone Github cvelistV5 repo", action="store_true")
    data_group.add_argument("--update", help="Check if there is any update from remote repo", action="store_true")

    search_group = arg.add_argument_group("Search CVE Arguments")
    search_group.add_argument("-s", "--search", help="Search CVE(s) in local database\n", action="store_true")

    arg.add_argument("-y", "--year", help="Specify the year for querying/searching CVEs")
    arg.add_argument("-i", "--id", help="Specify CVE id to search for")
    # arg.add_argument("-p", "--pattern", help="Specific search pattern to search from local database") # TODO: add this for regex match
    arg.add_argument("--create-metrics", help="Ensure that metrics will be created\n"
                     "If there is no metrics in JSON file, query metrics information from NVD", action="store_true")
    return arg


def dump_cvedb(cvedb: CVEdb, out_path: str = CVEdb.OUTPUT_PICKLE_FILE):
    print(f"Store cvedb to {out_path}")
    data = pickleutils.compress(pickleutils.serialize(cvedb))
    pickleutils.pickle_dump(out_path, data)


def load_or_create_cvedb():
    try:
        print(f"Loading cve database from {CVEdb.OUTPUT_PICKLE_FILE}")
        cvedb = pickleutils.pickle_load(CVEdb.OUTPUT_PICKLE_FILE)
        cvedb = pickleutils.deserialize(pickleutils.decompress(cvedb))
        return cvedb
    except:
        return CVEdb()


def handle_updated_cve(cvelist: CvelistHandler, files: list = [], args: argparse.Namespace = None):
    cvedb = load_or_create_cvedb()
    cve_handler = CVEHandler(cvelist.get_local_repo_path())
    for f in tqdm(files):
        path = pathutils.DEFAULT_PROJECT_LOCAL_REPO / f
        cve = cve_handler.create_cve_from_json(path)
        if cve.contains_metrics():
            cve.create_metrics(True)
        else:
            # TODO: call create_metrics when cli gives certain argument
            if args.create_metrics:
                cve.create_metrics(False)
        cvedb.upsert(cve)
    dump_cvedb(cvedb)


def handle_cve_json(cvelist: CvelistHandler, pattern: str = "**/CVE-*.json", args: argparse.Namespace = None):
    # TODO: add pattern to cli arguments
    # print(f"CVE Local Repo Path: {cvelist.get_local_repo_path()}")
    cvedb = load_or_create_cvedb()
    cve_handler = CVEHandler(cvelist.get_local_repo_path())
    for f in tqdm(cve_handler.get_cvelist_path().glob(pattern)):
    # for f in cve_handler.get_cvelist_path().glob("**/CVE-2013-3703.json"): # testing purpose, one JSON contains metrics
        cve = cve_handler.create_cve_from_json(f)
        if cve.contains_metrics():
            cve.create_metrics(True)
        else:
            # TODO: call create_metrics when cli gives certain argument
            if args.create_metrics:
                cve.create_metrics(False)
        cvedb.upsert(cve)
    dump_cvedb(cvedb)


def main():
    args = init_argparse().parse_args()
    # print(vars(args))

    if args.clone or args.update:
        if args.clone and args.update:
            raise Exception("Invalid arguments combination")
        repo = CvelistHandler()
        if args.clone:
            handle_cve_json(repo, args=args)
        elif args.update:
            updated = repo.find_updated_files()
            repo.pull_from_remote()
            handle_updated_cve(repo, files=updated, args=args)
    else:
        # TODO: search functions
        pass

if __name__ == "__main__":
    # cvelistv5_test()
    # cvehandler_test()
    # args = init_argparse().parse_args()
    # print(vars(args))

    # load from pickle test
    # data = pickle_load(CVEdb.OUTPUT_PICKLE_FILE)
    # cvedb = deserialize(decompress(data))
    # print(cvedb)
    main()