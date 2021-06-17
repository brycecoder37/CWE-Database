# Populating CWE/CVE Database
### Authors: Bryce Leighton & Tristan Chavez

**Description**

This repository contains Python code that can easily populate a Neo4j database with useful information regarding CWEs and CVEs. We used BeautifulSoup and Selenium to web scrape and automate the extraction of data. Within the Python program, it then stores this information inside of a Neo4j database, granted you have the database open while running the program.
<br />\
The next part of this project will be linking the Neo4j database to STIG, a tool developed by INL. Our goal to achieve this is to convert our Neo4j database into a JSON file which can be turned into a STIX bundle From there, we should be able to simply input the STIX bundle into STIG.

**Goals**
- [x] Create web scrapers to automate the data extraction
- [x] Populate a Neo4j database with CWE/CVE information
- [ ] Connect Neo4j database to STIG
- [ ] Find ways STIG can utilize our data 

**Technologies Used**
- Neo4j
- Python
  - *BeautifulSoup*
  - *Selenium*
- STIG - Structured Threat Intelligence Graph
  - *OrientDB*
  - *STIX*

**Resources**
- [CWE Info](https://cwe.mitre.org/)
- [CVE Info](https://cve.mitre.org/cve/)
- [STIX Documentation](https://oasis-open.github.io/cti-documentation/)
- [STIG Documentation](https://github.com/idaholab/STIG)

