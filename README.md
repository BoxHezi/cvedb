# cvedb

A local CVE db repository

1. Clone the [cvelistV5](https://github.com/CVEProject/cvelistV5) github repo
2. loop through all CVEs
   1. If there is no metrics information, query the CVE from NIST NVD Database
3. store in local database (json)
