# MSU Cybersecurity REU Project
## CWE/CVE Information Database
### Authors: Bryce Leighton & Tristan Chavez

**Description**

This repository contains Python code that can easily populate a Neo4j database with useful information regarding CWEs and CVEs. We used BeautifulSoup and Selenium to web scrape and automate the extraction of data. Within the Python program, it then stores this information inside of a Neo4j database, granted you have the database open while running the program.
<br />\
The next part of this project will be linking the Neo4j database to STIG, a tool developed by INL. Our goal to achieve this is to convert our Neo4j database into a JSON file whose syntax can be changed slightly so that it may be a valid input for STIX. From there, we should be able to simply input the STIX bundle(s) into STIG.

**Goals**
- [x] Create web scrapers to automate data extraction of CWEs/CVEs
- [x] Be able to populate a Neo4j database with CWE/CVE information
- [x] Convert Neo4j JSON export files into readable STIX JSON files
- [x] Import Neo4j JSON files to database to STIG
- [ ] Find ways STIG can utilize our data 

**Technologies Used**
- Neo4j
- Python
  - *BeautifulSoup*
- STIG - Structured Threat Intelligence Graph
  - *STIX*
  - *OrientDB*

**Resources**
- [CWE Info](https://cwe.mitre.org/)
- [CVE Info](https://nvd.nist.gov/)
- [STIX Documentation](https://oasis-open.github.io/cti-documentation/)
- [STIG Documentation](https://github.com/idaholab/STIG)

