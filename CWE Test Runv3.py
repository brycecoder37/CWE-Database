from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from urllib.request import urlopen as uReq
from bs4 import BeautifulSoup as soup
from neo4j import GraphDatabase
import bisect


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
    data_base_connection = GraphDatabase.driver(uri="bolt://localhost:11003", auth=("neo4j", "123"))
    session = data_base_connection.session()
    session.run(query)


# -----------------------------------------------------------------*
# binary search method returns -1 if not found, optimized for strings
# -----------------------------------------------------------------*

def string_binary_search(arr, low, high, x):
    if high >= low:

        mid = low + (high - low) // 2

        if arr[mid] == x:
            return True

        elif arr[mid] > x:
            return string_binary_search(arr, low, mid - 1, x)

        else:
            return string_binary_search(arr, mid + 1, high, x)

    else:
        return False


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
            query += "(" + CVEInput2 + ":CVE{name:\"" + CVEInput + "\", description:\"" + descriptions[0] \
                     + "\", severity:\"" + severity[0] + "\"})"

            # print(query) debug

            return query

        else:
            num += 1
            return cvesearch(CVEInput, query, num)
    except:
        print("No CVE found by the name of " + CVEInput)


# -----------------------------------------------------------------*
# scrapeCWE will scrape a CWE web page given its URL.
# -----------------------------------------------------------------*
#                           Parameters
# -----------------------------------------------------------------+
# CWE_id_number: ID of CWE that the method will scrape
# --------------
# usnode: the list of already-created nodes. This list will ensure
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

def scrapeCWE(CWE_id_number, usnode, Neo4jBoolean, cwe_cwe_bool, original_info):
    if not num_bin_search(usnode[2], CWE_id_number):
        bisect.insort(usnode[2], CWE_id_number)

    cwe_name = ""
    query = ""
    entire_cve_list = usnode[3]
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
                    if (temp.findNextSibling().contents[0] == "Technologies"):
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
    # Finding the Observed Examples of CVEs
    # ---------------------------------------------------->

    cve_list = []

    try:

        container = ps.find("div", {"id": "Observed_Examples"})

        first_div = container.div

        target_div = first_div.findNextSibling()

        cve_table = target_div.div.div.table

        cve_item = cve_table.tr

        for i in range(int(len(cve_table) / 2) - 1):
            cve_item = cve_item.findNextSibling()
            print("\"" + cve_item.a.contents[0] + "\"")

            if not string_binary_search(entire_cve_list, 0, len(entire_cve_list) - 1, cve_item.a.contents[0]):
                bisect.insort(entire_cve_list, cve_item.a.contents[0])
                # print(entire_cve_list) debug
                bisect.insort(cve_list, cve_item.a.contents[0])
                query = cvesearch(cve_item.a.contents[0], query, 0)
                query += ", (" + "CWE" + str(CWE_id_number) + ")-[:VULNERABLETO]->(" + cve_item.a.contents[0][0:3] + \
                         cve_item.a.contents[0][4:8] + cve_item.a.contents[0][9:] + ")"
            else:
                print("Duplicate CVE node")

                query += "\nWITH CWE" + str(CWE_id_number) + " \nMATCH(a:CVE {name:\"" + cve_item.a.contents[0] + \
                         "\"})\nCREATE (CWE" + str(CWE_id_number) + ")-[:VULNERABLETO]->(a) "
        print("CVE List: ", cve_list)
        print("There are", len(cve_list), "observed distinct CVEs.")
        print("")

        usnode[3] = entire_cve_list

    except:
        None

    # ---------------End of Observed CVEs-----------------X

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

        while (det_item != None):
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

            while (rel_cwe != None):
                relationships.append(rel_cwe.td.contents[0])
                id_numbers.append(int(rel_cwe.td.findNextSibling().findNextSibling().contents[0]))
                names.append(rel_cwe.td.findNextSibling().findNextSibling().findNextSibling().a.contents[0])
                rel_cwe = rel_cwe.findNextSibling()

            # Checks if there is more than one relationship table,
            # adds the relationships for the other tables if applicable
            # ----------------------------------------------------

            table_div = table_div.findNextSibling()

            while (table_div != None):
                even_further_div = table_div.div.div.div.div.div.table  # table tag
                target_div = even_further_div.tbody

                rel_cwe = target_div.tr

                while (rel_cwe != None):
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

    ##  Important Variables in scrapeCWE
    ##CWE_id_number
    ##cwe_name
    ##languages        #
    ##operating_systems# These 5 variables can merge
    ##architectures    # into 'applicable_platforms'
    ##paradigms        # variable
    ##technologies     #
    ##cve_list
    ##detection_methods
    ##exploit_likelihood
    ##paired_relationships

    # ---------------------------------------------------------------------->
    #
    #                             Neo4j CWE Import
    #
    # ---------------------------------------------------------------------->

    if Neo4jBoolean == True:

        variable_name = "CWE" + str(CWE_id_number)

        neo4j_create_statement = "create({0}:CWE {{name:"'"{1}"'",id_number:{2}".format(variable_name, cwe_name,
                                                                                        CWE_id_number)
        neo4j_create_statement += ",exploit_likelihood:"'"{}"'"}})".format(exploit_likelihood)

        if neo4j_create_statement != "create" and query[0:5] != "\nWITH" and query != "":
            # print(query[0:5]) debug
            neo4j_create_statement += ", " + query
        else:
            # print("MATCH STATEMENT") debug
            neo4j_create_statement += "\n" + query

        print("Neo4j create CWE statement: ", neo4j_create_statement)
        transaction(neo4j_create_statement)

        # --------------Applicable Platform Relationship Code-----------------

        count = 1
        apforms_sentence = "match (a:CWE) where a.id_number = {} ".format(CWE_id_number)
        create_section = "create "

        for language in languages:
            if language[0] not in usnode[0][0]:
                usnode[0][0].append(language[0])
                create_node = "create (a:Language {{name: "'"{}"'"}})".format(language[0])
                transaction(create_node)

            apforms_sentence += "match (a{0}:Language) where a{0}.name = "'"{1}"'" ".format(count, language[0])
            create_section += ",(a)-[:FOUNDIN {{prevalence:"'"{}"'"}}]->(a{})".format(language[1], count)
            count += 1

        for os in operating_systems:
            if os[0] not in usnode[0][1]:
                usnode[0][1].append(os[0])
                create_node = "create (a:OS {{name: "'"{}"'"}})".format(os[0])
                transaction(create_node)

            apforms_sentence += "match (a{0}:OS) where a{0}.name = "'"{1}"'" ".format(count, os[0])
            create_section += ",(a)-[:FOUNDIN {{prevalence:"'"{}"'"}}]->(a{})".format(os[1], count)
            count += 1

        for arch in architectures:
            if arch[0] not in usnode[0][2]:
                usnode[0][2].append(arch[0])
                create_node = "create (a:Architecture {{name: "'"{}"'"}})".format(arch[0])
                transaction(create_node)

            apforms_sentence += "match (a{0}:Architecture) where a{0}.name = "'"{1}"'" ".format(count, arch[0])
            create_section += ",(a)-[:FOUNDIN {{prevalence:"'"{}"'"}}]->(a{})".format(arch[1], count)
            count += 1

        for paradigm in paradigms:
            if paradigm[0] not in usnode[0][3]:
                usnode[0][3].append(paradigm[0])
                create_node = "create (a:Paradigm {{name: "'"{}"'"}})".format(paradigm[0])
                transaction(create_node)

            apforms_sentence += "match (a{0}:Paradigm) where a{0}.name = "'"{1}"'" ".format(count, paradigm[0])
            create_section += ",(a)-[:FOUNDIN {{prevalence:"'"{}"'"}}]->(a{})".format(paradigm[1], count)
            count += 1

        for tech in technologies:
            if tech[0] not in usnode[0][4]:
                usnode[0][4].append(tech[0])
                create_node = "create (a:Technology {{name: "'"{}"'"}})".format(tech[0])
                transaction(create_node)

            apforms_sentence += "match (a{0}:Technology) where a{0}.name = "'"{1}"'" ".format(count, tech[0])
            create_section += ",(a)-[:FOUNDIN {{prevalence:"'"{}"'"}}]->(a{})".format(tech[1], count)
            count += 1

        # Checks if the create section is just "create ", because that would mean
        # that there were no sections to add. If it isn't just "create ", then
        # it removes the first comma so that the create clause doesn't cause an error.
        if len(create_section) != 7:
            create_section = create_section[:7] + create_section[8:]
            final_statement = apforms_sentence + create_section
            transaction(final_statement)

        # -------------------------------------------------------------------X

        # ----------------Detection Methods Relationship Code-----------------

        count = 1
        detmet_sentence = "match (a:CWE) where a.id_number = {} ".format(CWE_id_number)
        create_section = "create "

        for detmet in detection_methods:

            if detmet[0] not in usnode[1]:
                usnode[1].append(detmet[0])
                create_node = "create (a:Detection_Method {{name: "'"{}"'"}})".format(detmet[0])
                transaction(create_node)

            detmet_sentence += "match (a{0}:Detection_Method) where a{0}.name = "'"{1}"'" ".format(count, detmet[0])

            # If this block of code causes an error, it means the detection method did not have
            # a listed effectiveness and will cause an error since it will not be a parsable string.
            # So, the effectiveness will just be listed as N/A for that detection method for the CWE.
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

        if len(create_section) != 7:
            create_section = create_section[:7] + create_section[8:]
            final_statement = detmet_sentence + create_section
            transaction(final_statement)

        # -------------------------------------------------------------------X

        # ------------------CWE - to - CWE Relationship Code------------------

        if cwe_cwe_bool is True:

            count = 1
            cwe_cwe_sentence = "match (a:CWE) where a.id_number = {} ".format(CWE_id_number)
            create_section = "create "

            for relation in paired_relationships:

                # For relationship CWEs that haven't been made yet.
                if not num_bin_search(usnode[2], relation[1]):
                    usnode = scrapeCWE(relation[1], usnode, True, False, [CWE_id_number, relation[0], None])

                # For relationship CWEs that HAVE been made already.
                else:

                    cwe_cwe_sentence += "match (a{0}:CWE) where a{0}.id_number = {1} ".format(count, relation[1])
                    create_section += ",(a)-[:{0}]->(a{1})".format(relation[0].upper(), count)
                    count += 1

            # If there are no relationships for a CWE, the length of create_section
            # ("create ") will be 7 and no clauses will be inputted into Neo4j.
            if len(create_section) != 7:
                # print("At the execution for already created node!!!!!!!!!!!!!!") debug
                create_section = create_section[:7] + create_section[8:]
                final_statement = cwe_cwe_sentence + create_section
                transaction(final_statement)

        else:

            cwe_cwe_sentence = "match (a:CWE) where a.id_number = {} ".format(original_info[0])
            cwe_cwe_sentence += "match (b:CWE) where b.id_number = {} ".format(CWE_id_number)
            final_statement = cwe_cwe_sentence + "create (a)-[:{}]->(b)".format(original_info[1].upper())
            transaction(final_statement)

        # -------------------------------------------------------------------X

        return usnode


# --------------------------------------End of Web Scraper Code---------------------------------------------------X


# -------------------Binary Search for Numbers----------------------->

def num_bin_search(list_to_check, target_number):
    left = 0
    right = len(list_to_check) - 1
    moves = 0
    while (left <= right):
        mid = int((left + right) / 2)
        moves += 1
        if (list_to_check[mid] == target_number):
            return True
        elif (list_to_check[mid] < target_number):
            left = mid + 1
        else:
            right = mid - 1

    return False


# -------------------------------------------------------X


# -------------------------Main Functions-------------------------->

def forMain(node_list):
    cwe_to_add = []
    answer = None

    usnode = node_list

    while True:
        answer = int(input("Enter CWE ID to put into database. Enter -1 to stop adding CWEs. "))
        if answer == -1:
            break
        cwe_to_add.append(answer)
    for cwe in cwe_to_add:
        print("----------------------------------------------")
        usnode = scrapeCWE(cwe, usnode, True, True, None)


# ----------------------------------------------------

def whileMain(node_list):
    id_num = None

    usnode = node_list

    while id_num != -1:
        print("----------------------------------------------")
        id_num = int(input("Enter ID of the CWE to scrape or -1 to end: "))
        if (id_num == -1):
            break
        usnode = scrapeCWE(id_num, usnode, True, True, None)


# ----------------------------------------------------

def addNeoInfo(node_list):
    num_of_cwe = int(input("How many CWEs would you like to add? "))
    check = input("Are you sure you want to import data to Neo4j? This requires an open Neo4j database.")
    last_check = input("Are you sure you wish to import data? Cancel program if not.")

    usnode = node_list

    for i in range(1, num_of_cwe + 1):
        usnode = scrapeCWE(i, usnode, True, True, None)


# --------------------------------------------------------X

# ------------------------------Main-------------------------------#

def main():
    used_nodes_list = [[[], [], [], [], []], [], [], []]
    ##    used_nodes_list[0] is the 5 applicable platforms
    ##    [0][0] - languages , [0][1] os , [0][2] architectures
    ##    [0][3] - paradigms , [0][4] technologies
    ##    ------------------------------------------------------
    ##    used_nodes_list[1] is the detection methods
    ##    used_nodes_list[2] is the CWE IDs
    ##    used_nodes_list[3] is the CVE IDs

    print("The for-loop or while-loop main?")
    print("Enter 1 for for-loop, 2 for while-loop, or 3 for Neo4j import.")
    answer = int(input("Enter number: "))
    if answer == 1:
        forMain(used_nodes_list)
    elif answer == 2:
        whileMain(used_nodes_list)
    elif answer == 3:
        addNeoInfo(used_nodes_list)


main()
