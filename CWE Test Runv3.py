from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from urllib.request import urlopen as uReq
from bs4 import BeautifulSoup as soup
from neo4j import GraphDatabase
import cwetools as ctools


# -----------------------------------------
# Last Updated : June 4                  |
# -----------------------------------------

# ------------------------------------------------------------------------->
#
#                           Web Scraper Code
#
# ------------------------------------------------------------------------->

# -----------------------------------------------------------------*
# input a query to neo4j
# -----------------------------------------------------------------*

def transaction(query):
    data_base_connection = GraphDatabase.driver(uri="bolt://localhost:11006", auth=("neo4j", "123"))
    session = data_base_connection.session()
    return session.run(query).single()


# -------------------Binary Search----------------------->

def binsearch(list_to_check, target_number):
    left = 0
    right = len(list_to_check) - 1
    moves = 0
    while left <= right:
        mid = int((left + right) / 2)
        moves += 1
        if list_to_check[mid] == target_number:
            return True
        elif list_to_check[mid] < target_number:
            left = mid + 1
        else:
            right = mid - 1

    return False


# -------------------------------------------------------X


# -----------------------------------------------------------------*
# cvesearch will scrape a cve web page given its URL.
# -----------------------------------------------------------------*

def cvesearch(CVEInput, query, num):
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    descriptions = []
    severity = []
    i = num
    sev = ""
    newName = ""
    query = query

    driver = webdriver.Chrome(
        executable_path='C:/Users/Tristan Chavez/Downloads/chromedriver_win32/chromedriver.exe',
        options=chrome_options)
    driver.get('https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&query=' + CVEInput +
               '&search_type=all')
    content = driver.page_source
    soup = BeautifulSoup(content, features="html.parser")
    view = "vuln-row-" + str(num)
    # print(view) debug

    try:
        c = soup.findAll('tr', attrs={'data-testid': view})
        # print(c) debug
        if c:
            for a in soup.findAll('tr', attrs={'data-testid': view}):
                newName = a.find('a').text
                # print(newName) debug

            if newName == CVEInput:
                for a in soup.findAll('tr', attrs={'data-testid': view}):
                    descr = a.find('p').text.replace('\\', r'\\\\').replace('"', r'\"')
                    descriptions.append(descr)
                for a in soup.findAll('td', attrs={'nowrap': 'nowrap'}):
                    sev = a.find('a')
                    if sev.text == "":
                        sev = a.find('a').next_sibling
                    if sev.text == "":
                        sev = "Not Applicable"
                    severity.append(sev.text)
                # print(descriptions[0]) debug
                # print(severity[0]) debug

                CVEInput2 = CVEInput[0:3] + CVEInput[4:8] + CVEInput[9:]
                # print(CVEInput2) debug

                if query != "":
                    query += ", "
                query += "(" + CVEInput2 + ":CVE{type: \"attack-pattern\", id: \"" + CVEInput[4:8] + "-" + \
                         CVEInput[9:] + "\", name:\"" + CVEInput + "\", description:\"" + descriptions[0] + \
                         "\", severity:\"" + severity[0] + "\"})"

                # print(query) debug

                return query

            else:
                num += 1
                return cvesearch(CVEInput, query, num)
        else:
            print("No CVE found by the name of " + CVEInput)
            return query
    except:
        None


# -----------------------------------------------------------------*
# scrapeCWE will scrape a CWE web page given its URL.
# -----------------------------------------------------------------*
#                           Parameters
# -----------------------------------------------------------------+
# CWE_id_number: ID of CWE that the method will scrape
# --------------
# that when the program is made for several CWEs, that it won't
# create duplicate nodes.
# --------------
# Neo4jBoolean: a simple True or False that will dictate whether the
# Neo4j import method for the CWE information is ran or not.
# ---------------
# cwe_cwe_bool: a boolean variable that determines whether the CWE
# will create relationships or not. If it is a CWE that was a branch
# of a relationship of an original node, it will not create any.
# ---------------
# original_info: contains the original CWE ID that the "branch" CWE
# came from and also contains a string that is the relationship
# between the original CWE and the "branch" CWE
# ------------------------------------------------------------------+

def scrapeCWE(CWE_id_number, Neo4jBoolean, cwe_cwe_bool, original_info):
    cwe_name = ""
    query = ""
    my_url = ""
    ps = ""

    try:

        # Choose url of CWE to be scraped

        my_url = ("https://cwe.mitre.org/data/definitions/{0}.html".format(CWE_id_number))

        uClient = uReq(my_url)
        page_html = uClient.read()
        uClient.close()

        ps = soup(page_html, "html.parser")

        # Web page is ready to scrape

        cwe_name = ps.h2.contents[0]  # Gets the title of the CWE

        print(cwe_name)
        print("")

    except:

        print("The url" + my_url + "does not exist.")
        print("")
        exit()

    # ---------------------------------------------------->
    # Finding the Applicable Platforms of the CWE
    # ---------------------------------------------------->

    # This code block finds the correct category, and then
    # proceeds to go to the correct div tag to work inside of.

    language_div = None
    temp = None

    try:
        container = ps.find("div", {"id": "Applicable_Platforms"})

        first_div = container.div
        target_div = first_div.findNextSibling()

        first_div = target_div.div.div
        language_div = first_div

        temp = language_div

    except:
        None

    # ------------------------------------------

    # Creates empty lists for all of the possible platforms
    # that the CWE could be in, so that they are ready to be
    # filled, if the scraper finds the corresponding category.

    languages = []
    operating_systems = []
    architectures = []
    paradigms = []
    technologies = []

    # ---------------Language-------------------

    try:
        if language_div.p.contents[0] == "Languages":
            temp = temp.findNext().findNext()

            for i in range(len(language_div) - 2):
                lang = temp.p.contents[0].strip()
                frequency = temp.p.span.contents[0].strip()
                languages.append([lang, frequency])
                try:
                    if temp.findNextSibling().contents[0] == "Technologies":
                        temp = temp.findNextSibling()
                        break
                except:
                    None
                temp = temp.findNextSibling()
    except:
        None

    # ------------Operating Systems-------------

    try:
        if temp.contents[0] == "Operating Systems" or language_div.p.contents[0] == "Operating Systems":
            temp = temp.findNextSibling()
            os = temp.p.contents[0].strip()
            frequency = temp.p.span.contents[0].strip()
            operating_systems.append([os, frequency])
            while temp.findNextSibling() != None:
                temp = temp.findNextSibling()
                os = temp.p.contents[0].strip()
                frequency = temp.p.span.contents[0].strip()
                operating_systems.append([os, frequency])
    except:
        None

    # --------------Architectures---------------

    try:
        if temp.contents[0] == "Architectures" or language_div.p.contents[0] == "Architectures":
            temp = temp.findNextSibling()
            arch = temp.p.contents[0].strip()
            frequency = temp.p.span.contents[0].strip()
            architectures.append([arch, frequency])
            while (temp.findNextSibling() != None):
                temp = temp.findNextSibling()
                arch = temp.p.contents[0].strip()
                frequency = temp.p.span.contents[0].strip()
                operating_systems.append([arch, frequency])
    except:
        None

    # ----------------Paradigms-----------------

    try:
        if temp.contents[0] == "Paradigms" or language_div.p.contents[0] == "Paradigms":
            temp = temp.findNextSibling()
            para = temp.p.contents[0].strip()
            frequency = temp.p.span.contents[0].strip()
            paradigms.append([para, frequency])
            while temp.findNextSibling() != None:
                temp = temp.findNextSibling()
                para = temp.p.contents[0].strip()
                frequency = temp.p.span.contents[0].strip()
                operating_systems.append([para, frequency])
    except:
        None

    # --------------Technologies----------------

    try:
        if temp.contents[0] == "Technologies" or language_div.p.contents[0] == "Technologies":
            temp = temp.findNextSibling()
            tech = temp.p.contents[0].strip()
            frequency = temp.p.span.contents[0].strip()
            technologies.append([tech, frequency])
            while temp.findNextSibling() != None:
                temp = temp.findNextSibling()
                tech = temp.p.contents[0].strip()
                frequency = temp.p.span.contents[0].strip()
                technologies.append([tech, frequency])
    except:
        None

    # ---------End of Applicable Platform Finders---------X

    # ---------------------------------------------------->
    # Finding the Common Consequences
    # ---------------------------------------------------->

    common_consequences = []

    try:
        container = ps.find("div", {"id": "Common_Consequences"})

        first_div = container.div
        target_div = first_div.findNextSibling()

        tbody_div = target_div.div.div.table

        temp = tbody_div.tr.findNextSibling()  # First common consequence row

        while temp != None:
            impacts = temp.i.contents[0].split("; ")
            impacts[0] = impacts[0].strip()
            scope = temp.td.contents[0::2]
            com_cons = ""
            for word in scope:
                com_cons += word + " "

            com_cons = com_cons[0:-1]

            common_consequences.append([com_cons, impacts])
            temp = temp.findNextSibling()


    except:
        None

    # ----------------------------------------------------X

    # ---------------------------------------------------->
    # Finding the Observed Examples of CVEs
    # ---------------------------------------------------->

    try:

        container = ps.find("div", {"id": "Observed_Examples"})

        first_div = container.div

        target_div = first_div.findNextSibling()

        cve_table = target_div.div.div.table

        cve_item = cve_table.tr

        for i in range(int(len(cve_table) / 2) - 1):
            cve_item = cve_item.findNextSibling()
            print("\"" + cve_item.a.contents[0] + "\"")

            node_exists = bool(transaction("MATCH(n:CVE {name: '" + cve_item.a.contents[0] + "'}) RETURN n"))
            # print(exists) debug
            if not node_exists:
                search = cvesearch(cve_item.a.contents[0], query, 0)
                if search != query:
                    query = search
                    query += ", (CWE" + str(CWE_id_number) + ")-[:VULNERABLETO]->(" + \
                             cve_item.a.contents[0][0:3] + cve_item.a.contents[0][4:8] + cve_item.a.contents[0][9:] \
                             + ")"
            else:
                # print("Duplicate CVE node") debug
                relationship_exist = bool(transaction("MATCH(a:CWE {id: " + str(CWE_id_number) +
                                                      "})-[:VULNERABLETO]->(b:CVE {name: '" + cve_item.a.contents[0] +
                                                      "'}) RETURN a"))
                if not relationship_exist:
                    query += "\nWITH CWE" + str(CWE_id_number) + " \nMATCH(a:CVE {name:\"" + cve_item.a.contents[0] + \
                             "\"})\nCREATE (CWE" + str(CWE_id_number) + ")-[:VULNERABLETO]->(a) "

    except:
        None

        # ---------------End of Observed CVEs-----------------X

        # ---------------------------------------------------->
        # Finding the Related Attack Patterns (CAPECs)
        # ---------------------------------------------------->

    # capec_list = []

    # try:

    #    container = ps.find("div", {"id": "Related_Attack_Patterns"})

    #    first_div = container.div

    #    target_div = first_div.findNextSibling()

    #    capec_table = target_div.div.div.table

    #    capec = capec_table.tr

    #    for i in range(int(len(capec_table) - 1 / 2)):
    #        capec = capec.findNextSibling()
    #        capec_name_div = capec.td
    #        capec_name = capec_name_div.a.contents[0]
    #        capec_desc = capec_name_div.findNextSibling().contents[0]
    #        capec_list.append([capec_name, capec_desc])

    # except:
    #   None

    # ---------------End of Finding CAPECs-----------------X

    # ---------------------------------------------------->
    # Finding the Detection Methods
    # ---------------------------------------------------->

    detection_methods = []

    try:
        container = ps.find("div", {"id": "Detection_Methods"})

        first_div = container.div
        target_div = first_div.findNextSibling()

        det_methods_table = target_div.div.div.table

        det_item = det_methods_table.tr

        while det_item is not None:
            method = det_item.td.p.contents[0].strip()
            try:
                effectiveness = (det_item.findAll("p"))[-1].contents[0]
                detection_methods.append([method, effectiveness])
            except:
                detection_methods.append(method)
            det_item = det_item.findNextSibling()

    except:
        None

    # --------------End of Detection Methods--------------X

    # ---------------------------------------------------->
    # Finding the Likelihood of Exploit
    # ---------------------------------------------------->

    exploit_likelihood = []

    try:
        container = ps.find("div", {"id": "Likelihood_Of_Exploit"})
        target_div = container.div.findNextSibling().div.div
        exploit_likelihood = target_div.contents[0]

    except:
        None

    # ------------End of Likelihood of Exploit------------X

    # ---------------------------------------------------->
    # Finding the CWE Relationships
    # ---------------------------------------------------->

    relationships = []
    id_numbers = []
    names = []
    paired_relationships = []

    if cwe_cwe_bool is True:
        try:

            # Adds the relationships for the first table

            container = ps.find("div", {"id": "Relationships"})

            # Takes a lot of digging to get to correct tag...
            first_div = container.div.findNextSibling()
            table_div = first_div.div.div.div  # references the specific table
            even_further_div = table_div.div.div.div.div.div.table
            target_div = even_further_div.tbody

            rel_cwe = target_div.tr

            while rel_cwe is not None:
                relationships.append(rel_cwe.td.contents[0])
                id_numbers.append(int(rel_cwe.td.findNextSibling().findNextSibling().contents[0]))
                names.append(rel_cwe.td.findNextSibling().findNextSibling().findNextSibling().a.contents[0])
                rel_cwe = rel_cwe.findNextSibling()

            # Checks if there is more than one relationship table,
            # adds the relationships for the other tables if applicable
            # ----------------------------------------------------

            table_div = table_div.findNextSibling()

            while table_div is not None:
                even_further_div = table_div.div.div.div.div.div.table  # table tag
                target_div = even_further_div.tbody

                rel_cwe = target_div.tr

                while rel_cwe is not None:
                    id_number = int(rel_cwe.td.findNextSibling().findNextSibling().contents[0])
                    name = rel_cwe.td.findNextSibling().findNextSibling().findNextSibling().a.contents[0]
                    if id_number not in id_numbers:
                        relationships.append(rel_cwe.td.contents[0])
                        id_numbers.append(id_number)
                        names.append(name)
                    rel_cwe = rel_cwe.findNextSibling()

                table_div = table_div.findNextSibling()

            for i in range(len(relationships)):
                paired_relationships.append([relationships[i], id_numbers[i], names[i]])

        except:
            None

    # -----------------End of Relationships---------------X

    # Important Variables in scrapeCWE
    # CWE_id_number
    # cwe_name
    # languages        #
    # operating_systems# These 5 variables can merge
    # architectures    # into 'applicable_platforms'
    # paradigms        # variable
    # technologies     #
    # cve_list
    # detection_methods
    # exploit_likelihood
    # paired_relationships

    # ---------------------------------------------------------------------->
    #
    #                             Neo4j CWE Import
    #
    # ---------------------------------------------------------------------->

    if Neo4jBoolean:

        neo4j_create_statement = ""

        variable_name = "CWE" + str(CWE_id_number)

        CWE_node_exists = bool(transaction("MATCH(n:CWE {id: " + str(CWE_id_number) + "}) RETURN n"))
        # print(CWE_node_exists) debug
        if not CWE_node_exists:
            neo4j_create_statement = "CREATE({0}:CWE {{type:'vulnerability', name:"'"{1}"'",id:{2}".format(
                variable_name, cwe_name,
                CWE_id_number)
            neo4j_create_statement += ",exploit_likelihood:"'"{}"'"}})".format(exploit_likelihood)

        if neo4j_create_statement != "CREATE" and query[0:5] != "\nWITH" and query != "":
            if neo4j_create_statement == "":
                neo4j_create_statement = "CREATE " + query
            else:
                # print(query[0:5]) debug
                neo4j_create_statement += ", " + query
        else:
            # print("MATCH STATEMENT") debug
            neo4j_create_statement += "\n" + query

        # print("Neo4j create CWE statement: " + neo4j_create_statement) debug
        if neo4j_create_statement != "\n":
            transaction(neo4j_create_statement)

        # --------------Applicable Platform Relationship Code-----------------

        count = 1
        apforms_sentence = "MATCH (a:CWE) WHERE a.id = {} ".format(CWE_id_number)
        create_section = "CREATE "

        for language in languages:
            language_node_exists = bool(transaction("MATCH(n:Language {name: '" + language[0] + "'}) RETURN n"))
            if not language_node_exists:
                create_node = "CREATE (a:Language {{type: 'infrastructure', id:"'"{0}"'", name: "'"{1}"'"}})" \
                    .format(language[0], language[0])
                transaction(create_node)

            language_relationship_exist = bool(transaction("MATCH(a:CWE {id: " + str(CWE_id_number) +
                                                           "})-[:FOUNDIN]->(b:Language {name: '" + language[0] +
                                                           "'}) RETURN a"))
            if not language_relationship_exist:
                apforms_sentence += "MATCH (a{0}:Language) WHERE a{0}.name = "'"{1}"'" ".format(count, language[0])
                create_section += ",(a)-[:FOUNDIN {{prevalence:"'"{}"'"}}]->(a{})".format(language[1], count)
            count += 1

        for os in operating_systems:
            os_node_exists = bool(transaction("MATCH(n:OS {name: '" + os[0] + "'}) RETURN n"))
            if not os_node_exists:
                create_node = "CREATE (a:OS {{type: 'infrastructure', id: "'"{0}"'", name: "'"{1}"'"}})" \
                    .format(os[0], os[0])
                transaction(create_node)

            os_relationship_exist = bool(transaction("MATCH(a:CWE {id: " + str(CWE_id_number) +
                                                     "})-[:FOUNDIN]->(b:OS {name: '" + os[0] +
                                                     "'}) RETURN a"))
            if not os_relationship_exist:
                apforms_sentence += "MATCH (a{0}:OS) WHERE a{0}.name = "'"{1}"'" ".format(count, os[0])
                create_section += ",(a)-[:FOUNDIN {{prevalence:"'"{}"'"}}]->(a{})".format(os[1], count)
            count += 1

        for arch in architectures:
            arch_node_exists = bool(transaction("MATCH(n:Architecture {name: '" + arch[0] + "'}) RETURN n"))
            if not arch_node_exists:
                create_node = "CREATE (a:Architecture {{type: 'infrastructure', id: "'"{0}"'", name: "'"{1}"'"}})" \
                    .format(arch[0], arch[0])
                transaction(create_node)

            arch_relationship_exist = bool(transaction("MATCH(a:CWE {id: " + str(CWE_id_number) +
                                                       "})-[:FOUNDIN]->(b:Architecture {name: '" + arch[0] +
                                                       "'}) RETURN a"))
            if not arch_relationship_exist:
                apforms_sentence += "MATCH (a{0}:Architecture) where a{0}.name = "'"{1}"'" ".format(count, arch[0])
                create_section += ",(a)-[:FOUNDIN {{prevalence:"'"{}"'"}}]->(a{})".format(arch[1], count)
            count += 1

        for paradigm in paradigms:
            paradigm_node_exists = bool(transaction("MATCH(n:Paradigm {name: '" + paradigm[0] + "'}) RETURN n"))
            if not paradigm_node_exists:
                create_node = "CREATE (a:Paradigm {{type: 'observed-data', id: "'"{0}"'", name: "'"{1}"'"}})" \
                    .format(paradigm[0], paradigm[0])
                transaction(create_node)

            paradigm_relationship_exist = bool(transaction("MATCH(a:CWE {id: " + str(CWE_id_number) +
                                                           "})-[:FOUNDIN]->(b:Paradigm {name: '" + paradigm[0] +
                                                           "'}) RETURN a"))
            if not paradigm_relationship_exist:
                apforms_sentence += "MATCH (a{0}:Paradigm) where a{0}.name = "'"{1}"'" ".format(count, paradigm[0])
                create_section += ",(a)-[:FOUNDIN {{prevalence:"'"{}"'"}}]->(a{})".format(paradigm[1], count)
            count += 1

        for tech in technologies:
            tech_node_exists = bool(transaction("MATCH(n:Technology {name: '" + tech[0] + "'}) RETURN n"))
            if not tech_node_exists:
                create_node = "CREATE (a:Technology {{type: 'infrastructure', id: "'"{0}"'", name: "'"{1}"'"}})" \
                    .format(tech[0], tech[0])
                transaction(create_node)

            tech_relationship_exist = bool(transaction("MATCH(a:CWE {id: " + str(CWE_id_number) +
                                                       "})-[:FOUNDIN]->(b:Technology {name: '" + tech[0] +
                                                       "'}) RETURN a"))
            if not tech_relationship_exist:
                apforms_sentence += "MATCH (a{0}:Technology) WHERE a{0}.name = "'"{1}"'" ".format(count, tech[0])
                create_section += ",(a)-[:FOUNDIN {{prevalence:"'"{}"'"}}]->(a{})".format(tech[1], count)
            count += 1

        # -------------------------------------------------------------------X

        if create_section != "CREATE ":
            create_section = create_section[:7] + create_section[8:]
            final_statement = apforms_sentence + create_section
            # print(final_statement) debug
            transaction(final_statement)

        # -----------------------CAPECs Relationship Code---------------------

        # create_section = "CREATE "
        # final_statement = ""

        # for capec in capec_list:
        #    capec_node_exists = bool(transaction("MATCH(n:CAPEC {id_number: '" + capec[0][6:] + "'}) RETURN n"))
        #    if not capec_node_exists:
        #        create_node = "CREATE (a{2}:CAPEC {{id_number: {0}, description: "'"CAPEC-{0}: {1}"'"}})".format(
        #            str(capec[0][6:]), capec[1], count)
        #        print(capec[1])
        #        transaction(create_node)

        #    capec_relationship_exist = bool(transaction("MATCH(a:CAPEC {id_number: " + str(capec[0][6:]) +
        #                                                "})<-[:ATTACKPATTERNFOR]-(b:CWE {name: '" +
        #                                                str(CWE_id_number) + "'}) RETURN a"))
        #    print(capec_relationship_exist)
        #    if not capec_relationship_exist:
        #        apforms_sentence += "MATCH (a{0}:CAPEC) WHERE a{0}.id_number = {1} ".format(count, str(capec[0][6:]))
        #        create_section += ",(a)<-[:ATTACKPATTERNFOR]-(a{})".format(count)
        #    count += 1

        # -------------------------------------------------------------------X

        # ----------------Common Consequences Relationship Code---------------

        create_section = "CREATE "
        final_statement = ""

        for consequence in common_consequences:

            consequence_node_exists = bool(transaction("MATCH(n:Consequence {name: '" + consequence[0] + "'})"
                                                                                                         " RETURN n"))
            if not consequence_node_exists:
                create_node = "CREATE (a:Consequence {{type: 'observed-data', id: "'"{0}"'", name: "'"{1}"'"}})". \
                    format(consequence[0], consequence[0])
                transaction(create_node)

            consequence_relationship_exist = bool(transaction("MATCH(a:CWE {id: " + str(CWE_id_number) +
                                                              "})-[:VIOLATES]->(b:Consequence {name: '" +
                                                              consequence[0] + "'}) RETURN a"))

            if not consequence_relationship_exist:
                apforms_sentence += "MATCH (a{0}:Consequence) WHERE a{0}.name = "'"{1}"'" ".format(count,
                                                                                                   consequence[0])
                create_section += ",(a)-[:VIOLATES]->(a{})".format(count)

            count += 1
            cons_match_count = count

            for impact in consequence[1]:
                impact_node_exists = bool(transaction("MATCH(n:Impact {name: '" + impact + "'}) RETURN n"))
                if not impact_node_exists:
                    create_node = "CREATE (b:Impact {{type: 'observed-data', id: "'"{0}"'", name: "'"{1}"'"}})" \
                        .format(impact, impact)
                    transaction(create_node)

                impact_relationship_exist = bool(transaction("MATCH (b:Consequence {name: '" + consequence[0] +
                                                             "'})-[:CAUSES]->(c:Impact {name: '" + impact +
                                                             "'}) RETURN b"))

                if not impact_relationship_exist:
                    apforms_sentence += "MATCH (b{0}:Consequence) WHERE b{0}.name = "'"{1}"'" ".format(cons_match_count,
                                                                                                       consequence[0])
                    apforms_sentence += "MATCH (c{0}{1}:Impact) WHERE c{0}{1}.name = "'"{2}"'" ".format(
                        cons_match_count, count, impact)
                    create_section += ", (b{0})-[:CAUSES]->(c{0}{1})".format(cons_match_count, count)

                count += 1
            count = cons_match_count

        # -------------------------------------------------------------------X

        if create_section != "CREATE ":
            create_section = create_section[:7] + create_section[8:]
            final_statement = apforms_sentence + create_section
            # print(final_statement) debug
            transaction(final_statement)

        # -----------------------Tools Relationship Code----------------------

        if "Class: Language-Independent" in ([i[0] for i in languages]):
            for tool in ctools.all_tools:
                for product in tool[1:]:
                    if binsearch(product[1:], CWE_id_number):
                        apforms_sentence += "MATCH (a{0}:Tool) WHERE a{0}.name = "'"{1}"'" ".format(count,
                                                                                                    product[0])
                        tools_relationship_exist = bool(transaction("MATCH(a:CWE {id: " + str(CWE_id_number) +
                                                                    "})<-[:FINDS]-(b:Tool {name: \"" +
                                                                    product[0] + "\"}) RETURN a"))
                        create_section = "CREATE "

                        if not tools_relationship_exist:
                            create_section += ", (a)<-[:FINDS]-(a{})".format(count)
                            create_section = create_section[:7] + create_section[8:]
                            final_statement = apforms_sentence + create_section
                            transaction(final_statement)
                        count += 1
        else:
            for tool in ctools.all_tools:
                if tool[0] in ([i[0] for i in languages]):
                    for product in tool[1:]:
                        if binsearch(product[1:], CWE_id_number):
                            apforms_sentence += "MATCH (a{0}:Tool) WHERE a{0}.name = "'"{1}"'" ".format(count,
                                                                                                        product[0])
                            tools_relationship_exist = bool(transaction("MATCH(a:CWE {id: " + str(CWE_id_number) +
                                                                        "})<-[:FINDS]-(b:Tool {name: \"" +
                                                                        product[0] + "\"}) RETURN a"))
                            create_section = "CREATE "

                            if not tools_relationship_exist:
                                create_section += ", (a)<-[:FINDS]-(a{})".format(count)
                                create_section = create_section[:7] + create_section[8:]
                                final_statement = apforms_sentence + create_section
                                transaction(final_statement)
                            count += 1

        all_tools = ctools.get_tools()
        for tool in all_tools:
            for language in tool[1]:
                language_node_exists = bool(transaction("MATCH(n:Language {name: '" + language + "'}) RETURN n"))
                if language_node_exists:
                    language_tool_relationship_exists = bool(transaction("MATCH(a:Tool {id: " +
                                                                         str(tool[0])[1:len(str(tool[0])) - 1] +
                                                                         "})-[:USEDFOR]->(b:Language {name: '" +
                                                                         language + "'}) RETURN a"))
                    if not language_tool_relationship_exists:
                        transaction("MATCH(a:Tool {id: " + str(tool[0])[1:len(str(tool[0])) - 1] +
                                    "}) MATCH(b:Language {name: '" + language + "'}) CREATE (a)-[:USEDFOR]->(b)")
                        print("MATCH(a:Tool {id: " + str(tool[0])[1:len(str(tool[0])) - 1] +
                              "}) MATCH(b:Language {name: '" + language + "'}) CREATE (a)-[:USEDFOR]->(b)")

        # -------------------------------------------------------------------X

        # ----------------Detection Methods Relationship Code-----------------

        count = 1
        detmet_sentence = "MATCH (a:CWE) WHERE a.id = {} ".format(CWE_id_number)
        create_section = "CREATE "

        for detmet in detection_methods:

            detmet_node_exists = bool(transaction("MATCH(n:Detection_Method {name: '" + detmet[0] + "'}) RETURN n"))
            if not detmet_node_exists:
                create_node = "CREATE (a:Detection_Method {{type: 'observed-data', id: "'"{0}"'", name: "'"{1}"'"}})" \
                    .format(detmet[0], detmet[0])
                transaction(create_node)

            detmet_sentence += "MATCH (a{0}:Detection_Method) WHERE a{0}.name = "'"{1}"'" ".format(count, detmet[0])

            # If this block of code causes an error, it means the detection method did not have
            # a listed effectiveness and will cause an error since it will not be a parsable string.
            # So, the effectiveness will just be listed as N/A for that detection method for the CWE.
            detmet_relationship_exist = bool(transaction("MATCH(a:CWE {id: " + str(CWE_id_number) +
                                                         "})-[:DETECTEDBY]->(b:Detection_Method {name: '" + detmet[0] +
                                                         "'}) RETURN a"))

            if not detmet_relationship_exist:
                try:
                    if detmet[1][0] != " ":
                        effectiveness = " ".join(detmet[1].split(" ")[1:])
                        create_section += ",(a)-[:DETECTEDBY {{effectiveness:"'"{}"'"}}]->(a{})".format(effectiveness,
                                                                                                        count)
                    else:
                        create_section += ",(a)-[:DETECTEDBY {{effectiveness:"'"N/A"'"}}]->(a{})".format(count)
                    count += 1
                except:
                    create_section += ",(a)-[:DETECTEDBY {{effectiveness:"'"N/A"'"}}]->(a{})".format(count)
                    count += 1

        if create_section != "CREATE ":
            create_section = create_section[:7] + create_section[8:]
            final_statement = detmet_sentence + create_section
            transaction(final_statement)

        # -------------------------------------------------------------------X

        # ------------------CWE - to - CWE Relationship Code------------------

        if cwe_cwe_bool is True:

            count = 1
            cwe_cwe_sentence = "MATCH (a:CWE) WHERE a.id = {} ".format(CWE_id_number)
            create_section = "CREATE "

            for relation in paired_relationships:
                scrapeCWE(relation[1], True, False, [CWE_id_number, relation[0], None])

            # If there are no relationships for a CWE, the length of create_section
            # ("create ") will be 7 and no clauses will be inputted into Neo4j.
            if len(create_section) != 7:
                # print("At the execution for already created node!!!!!!!!!!!!!!") debug
                create_section = create_section[:7] + create_section[8:]
                final_statement = cwe_cwe_sentence + create_section
                transaction(final_statement)

        else:
            cwe_relationship_exist = bool(transaction("MATCH(a:CWE {id: " + str(original_info[0]) +
                                                      "})-[:" + original_info[1].upper() + "]->(b:CWE {id: " +
                                                      str(CWE_id_number) + "}) RETURN a"))

            if not cwe_relationship_exist:
                cwe_cwe_sentence = "MATCH (a:CWE) where a.id = {} ".format(original_info[0])
                cwe_cwe_sentence += "MATCH (b:CWE) where b.id = {} ".format(CWE_id_number)
                final_statement = cwe_cwe_sentence + "CREATE (a)-[:{}]->(b)".format(original_info[1].upper())
                transaction(final_statement)

        # -------------------------------------------------------------------X


# --------------------------------------End of Web Scraper Code---------------------------------------------------X

# ------------------Tool Node Creation Code------------------

def create_tools():
    tool_list = ctools.get_tools()
    create_nodes = ""
    num = 0
    for tool in tool_list:
        tool_node_exists = bool(transaction("MATCH (n:Tool) WHERE n.id = " +
                                            str(tool[0])[1:len(str(tool[0])) - 1] + " RETURN n"))

        if not tool_node_exists:
            languages = ""
            for language in tool[1]:
                newLang = str(language)
                if languages != "":
                    languages += ", "
                languages += newLang

            create_nodes += "(t" + str(num) + ":Tool {name:\"" + str(tool[0])[2:len(str(tool[0])) - 2] + \
                            "\", id:\"" + str(tool[0])[2:len(str(tool[0])) - 2] + "\", type: \"tool\", languages:\"" + \
                            languages + "\"}), "
            print("(t" + str(num) + ":Tool {name:\"" + str(tool[0])[2:len(str(tool[0])) - 2] + \
                  "\", id:\"" + str(tool[0])[2:len(str(tool[0])) - 2] + "\", type: \"tool\", languages:\"" + \
                  languages + "\"}), ")

        num += 1
    if create_nodes != "":
        # print("CREATE " + create_nodes[:len(create_nodes) - 2]) debug
        transaction("CREATE " + create_nodes[:len(create_nodes) - 2])


# ----------------------------------------------------

# -------------------------Main Functions-------------------------->

def forMain():
    cwe_to_add = []
    answer = None

    while True:
        answer = int(input("Enter CWE ID to put into database. Enter -1 to stop adding CWEs. "))
        if answer == -1:
            break
        cwe_to_add.append(answer)
    for cwe in cwe_to_add:
        print("----------------------------------------------")
        scrapeCWE(cwe, True, True, None)


# ----------------------------------------------------

def whileMain():
    id_num = None

    while id_num != -1:
        print("----------------------------------------------")
        id_num = int(input("Enter ID of the CWE to scrape or -1 to end: "))
        if id_num == -1:
            break
        scrapeCWE(id_num, True, True, None)


# ----------------------------------------------------

def addNeoInfo():
    num_of_cwe = int(input("How many CWEs would you like to add? "))

    for i in range(1, num_of_cwe + 1):
        scrapeCWE(i, True, True, None)


# --------------------------------------------------------X

# ------------------------------Main-------------------------------#

def main():
    print("The for-loop or while-loop main?")
    print("Enter 1 for for-loop, 2 for while-loop, or 3 for Neo4j import.")
    answer = int(input("Enter number: "))
    print("Checking database for tools, this may take a while...")

    create_tools()

    if answer == 1:
        forMain()
    elif answer == 2:
        whileMain()
    elif answer == 3:
        addNeoInfo()


main()
