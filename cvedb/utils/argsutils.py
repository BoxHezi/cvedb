import argparse


def init_argparse() -> argparse.ArgumentParser:
    arg = argparse.ArgumentParser(description="CVE Local database in JSON format", formatter_class=argparse.RawTextHelpFormatter)
    db_group = arg.add_argument_group("CVE Database Arguments")
    db_group.add_argument("--clone", help="Clone Github cvelistV5 repo", action="store_true")
    db_group.add_argument("--update", help="Check if there is any update from remote repo", action="store_true")
    db_group.add_argument("--create-metrics", help="Create Metrics for CVEs no matter JSON contains metrics entry\n"
                     "If there is no metrics in JSON file, query metrics information from NVD\n"
                     "This can lead to long run of the program, since most JSON doesn't contain metrics entry", action="store_true")

    search_group = arg.add_argument_group("Search CVE Arguments")
    search_group.add_argument("-s", "--search", help="Search CVE(s) in local database\n", action="store_true")
    search_group.add_argument("-o", "--out", help="Specify output path, JSON format supported.")
    search_group.add_argument("-p", "--pattern", help="Specific search pattern to search from local database")
    search_group.add_argument("-y", "--year", help="Specify the year for searching CVEs\n"
                              "This will return a Table instance")
    search_group.add_argument("-i", "--id", help="Specify CVE id to search for\n"
                              "This will return a CVE instance")

    arg.add_argument("-v", "--version", help="Print version", action="store_true")
    return arg


def process_year_or_id(args: argparse.Namespace) -> str:
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


def process_pattern(pattern: str):
    """
    Process a string pattern and generate a regular expression (regex) based on the pattern.

    The pattern is a string of words separated by spaces. Each word represents a match condition.
    If a word starts with "-", it represents a negative match condition, otherwise it represents a positive match condition.

    :param pattern: The pattern string to be processed.
    :return: A regex string that matches any string satisfying all the positive and negative match conditions.

    :Example:

    >>> process_pattern("apple -orange")
    '(?=.*apple)(^((?!orange).)*$)'

    This will return a regex that matches any string that contains "apple" and does not contain "orange".
    """
    # if pattern:
    pattern_list = pattern.split(" ")
    positive_match = [p for p in pattern_list if not p.startswith("-")]
    negative_match = [p[1:] for p in pattern_list if p.startswith("-")]

    pos_regex = "".join(f"(?=.*{m})" for m in positive_match)
    neg_regex = f"(^((?!{'|'.join(negative_match)}).)*$)" if negative_match else ""

    return pos_regex + neg_regex
    # return r"()"

