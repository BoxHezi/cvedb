import json
from tqdm import tqdm
from pprint import pprint

from .utils import pickleutils
from .utils import pathutils
from .utils import argsutils
from .utils import pipeutils

from .DatabaseServices.NVDFeedsHandler import *
from .DatabaseServices.DatabaseDriver import Database
from .DatabaseServices.DatabaseModels import CVE as NVDCVE
from .DatabaseServices.DatabaseModels import Description, Metrics, Weakness, Reference, AffectConfiguration, AffectConfigurationPartner

from .version import __version__


def init_db(model=NVDCVE, echo=False):
    return Database(model=model, echo=echo)


def process_description(cve, content):
    for d in content:
        yield Description(cve.get_id(), **d)


def process_metrics(cve, content):
    if "cvssMetricV2" in content:
        for mv2 in content["cvssMetricV2"]:
            yield Metrics(cve.get_id(), 2, **mv2)
    if "cvssMetricV30" in content:
        for mv30 in content["cvssMetricV30"]:
            yield Metrics(cve.get_id(), 3, **mv30)
    if "cvssMetricV31" in content:
        for mv31 in content["cvssMetricV31"]:
            yield Metrics(cve.get_id(), 3.1, **mv31)


def process_weakness(cve, content):
    for w in content:
        yield Weakness(cve.get_id(), **w)


def process_affect_configuration(cve, content):
    conf_id = 0
    for conf in content:
        if conf.get("operator") == "AND" and len(conf["nodes"]) > 1:
            for soft in conf["nodes"][0]["cpeMatch"]:
                affect_conf = AffectConfiguration(cve.get_id(), conf_id, **soft)
                yield affect_conf
                for base in conf["nodes"][1]["cpeMatch"]:
                    yield AffectConfigurationPartner(cve.get_id(), conf_id, affect_conf.get_match_criterid_id(), **base)
        else:
            for cpes in conf["nodes"]:
                for cpe in cpes["cpeMatch"]:
                    yield AffectConfiguration(cve.get_id(), conf_id, **cpe)
        conf_id += 1


def process_reference(cve, content):
    ref_id = 0
    for refs in content:
        yield Reference(cve.get_id(), ref_id, **refs)
        ref_id += 1


def parse_cve_json(file_path, db):
    json_content = {}
    with open(file_path, "r") as f:
        json_content = json.load(f)

    insert_list = []
    # CVE
    cve = NVDCVE(**json_content)
    insert_list.append(cve)
    # print(cve.get_id())

    # Descriptions
    insert_list += list(process_description(cve, json_content["descriptions"]))
    # Metrics
    if "metrics" in json_content:
        insert_list += list(process_metrics(cve, json_content["metrics"]))
    # Weakness
    if "weaknesses" in json_content:
        insert_list += list(process_weakness(cve, json_content["weaknesses"]))
    # Affect Configuration
    if "configurations" in json_content:
        insert_list += list(process_affect_configuration(cve, json_content["configurations"]))
    # Reference
    if "references" in json_content:
        insert_list += list(process_reference(cve, json_content["references"]))

    # insert into database
    # with open("db_log.txt", "a") as writer:
    #     writer.write(f"{str(cve.get_id())} - {len(insert_list)}\n")
    session = db.get_session()
    session.add_all(insert_list)
    # for i in insert_list:
    #     session.add(i)
    session.commit()
    # return cve


def main():
    nvd_handler = NVDFeedsHandler()
    # print(nvd_handler)

    db = init_db(NVDCVE, False)
    # print(db)

    print(nvd_handler.local_repo_path)

    cve_path = pathutils.open_path(nvd_handler.local_repo_path)
    for f in tqdm(cve_path.glob("**/CVE-*.json"), disable=False):
        # with open(f, "r") as file:
            # json.load(file)
        parse_cve_json(f, db)
        # break

    # args = argsutils.init_argparse().parse_args()
    # if args.version:
    #     print(f"CVEdb - {__version__}")
    # elif args.clone or args.update:
    #     clone_or_update(args)
    # elif args.search:
    #     cvedb = init_db()
    #     if args.year:
    #         table = search(cvedb, int(args.year), None, args.pattern)
    #         table and print(table)
    #     else:
    #         if not args.id and pipeutils.has_pipe_data():
    #             args.id = pipeutils.read_from_pipe()
    #         else:
    #             args.id = args.id.strip().split(" ")  # convert cmd arguments into list

    #         data = search(cvedb, None, args.id, args.pattern)
    #         for cve in data:
    #             print(str(cve))
        # print(json.dumps(jsonlialize_cve(data), indent=2))
        # print(type(data))


if __name__ == "__main__":
    main()

# __all__ = ["CVEdb"]
