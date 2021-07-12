# CWE/CVE Neo4j Database
### Authors: Bryce Leighton & Tristan Chavez

---

**Description**

This repository contains import data that can be used to view a CWE database in either your own Neo4j desktop, but can also be viewed in [**Neo4j Aura**](https://neo4j.com/cloud/aura/) with ease. Also included is the Python code that was used to initially populate the Neo4j database with useful information regarding CWEs and CVEs. We used BeautifulSoup to web scrape and automate the extraction of data. Within the Python program, it then stores this information inside of a Neo4j database, granted you have the database open while running the program.

>###  Please read the directions [**here**](https://github.com/brycecoder37/CWE-Database/blob/main/View-Instructions.md) for importing and viewing our Neo4j database.

The next part of this project will be linking the Neo4j database to STIG, a tool developed by INL. Our goal to achieve this is to convert our Neo4j database into readable JSON  by STIX. From there, we should be able to create and input STIX bundles into STIG.

---

**Goals**
- [x] Create web scrapers to automate data extraction of CWEs/CVEs.
- [x] Be able to populate a Neo4j database with CWE/CVE information.
- [x] Provide an easy and simple way for anyone to view the database.
- [x] Convert Neo4j JSON export files into readable STIX JSON files.
- [x] Import Neo4j JSON files to database to STIG.
- [ ] Find ways STIG can utilize our data.

---

**Technologies Used**
- Neo4j
- Python
  - *BeautifulSoup*
- STIG - Structured Threat Intelligence Graph
  - *STIX*
  - *OrientDB*

---

**Resources**
- [CWE Info](https://cwe.mitre.org/)
- [CVE Info](https://nvd.nist.gov/)
- [STIX Documentation](https://oasis-open.github.io/cti-documentation/)
- [STIG Documentation](https://github.com/idaholab/STIG)

