import argparse


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
    arg.add_argument("-v", "--version", help="Print version", action="store_true")
    # arg.add_argument("-p", "--pattern", help="Specific search pattern to search from local database") # TODO: add this for regex match
    return arg


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