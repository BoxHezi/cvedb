# cvedb

A local CVE db repository

1. Clone the [cvelistV5](https://github.com/CVEProject/cvelistV5) github repo
2. loop through all CVEs
   1. CVE instance will be created based on CVE json file
      1. If the CVE json file contains metrics entry, create Metrics for the CVE
      2. Otherwise, if `--create-metrics` argument is given, fetch metrics from NVD and create Metrics for the CVE
3. store in local database (python pickle)
