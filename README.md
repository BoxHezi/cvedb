# cvedb

A local CVE db repository

1. Clone the [cvelistV5](https://github.com/CVEProject/cvelistV5) github repo
2. loop through all CVEs
   1. CVE instance will be created based on CVE json file
      1. If the CVE json file contains metrics entry, create Metrics for the CVE
      2. Otherwise, if `--create-metrics` argument is given, fetch metrics from NVD and create Metrics for the CVE
3. store in local database (python pickle)

# Installation

Use pip command to install:

```python
pip install py-cvedb
```

# Usage

## Command Line

1. Use `cvedb --clone` to clone the [cvelistV5 repo](https://github.com/CVEProject/cvelistV5) and init the local data
   1. This action will first check if [cvelistV5 repo](https://github.com/CVEProject/cvelistV5) is cloned.
      1. If not cloned yet, clone the repo first
      2. Then, loop through all CVE JSON file and create CVE instance
   2. The local database will be dumped to a compressed pickle file located in `$HOME/.config/cvedb/cvedb.pickle`
2. Use `cvedb --update` to check if there contains update from [cvelistV5 repo](https://github.com/CVEProject/cvelistV5)
   1. If contains detected
      1. Firstly, get all updated file
      2. Re-create CVE instance and do update or insert to local database

> 1. The [cvelistV5 repo](https://github.com/CVEProject/cvelistV5) take several minutes to clone, actual time taken is affected by Internet connection

## Search

Use `cvedb -s` or `cvedb --search` to search from database

1. using `-y` or `--year` to get CVEs in a specific year
   1. Adding `-p` or `--pattern` to filter out CVE records. Give a string start will `-` for negative match.
      1. If given `injection -database` will get all records contains `injection` but not `database`.
2. using `-i` or `--id` to get CVE with a specific CVE id

## Use it in python project

```python
>>> from cvedb import cvedb
>>>
>>> cvedb = cvedb.init_db()
>>> type(cvedb) # <class 'cvedb.cvedb.CVEdb'>
```
