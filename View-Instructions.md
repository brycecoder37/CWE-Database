## How to Import the Database for Use
---
> ***First***, download the database files [**here**](https://github.com/brycecoder37/CWE-Database/tree/main/Import%20Data).
---
### If you *do not* have Neo4j downloaded:
1. Go to [Neo4j Aura](https://neo4j.com/cloud/aura/).  -----**Important:** *Currently Neo4j Aura does not work for 4.3.2 dump files, but they are supposedly close to resolving it*
2. Create Neo4j account.
3. Click on `create database`.
4. Choose free version (top option), and click `create database` at the bottom.
5. **Important:** Copy the generated password it gives to you.
6. Once the database has transitioned from "*loading*" to "*running*", <br> 
   click on the database name which will then drop down a menu.
7. In the "*import database*" tab, click on `select a .dump file`, <br> 
   and choose neo4j.dump as the file to import.
8. Once the database is running, select to open in Neo4j browser.
9. Enter in `neo4j` as the username and paste the given password.
10. Drag and drop the Style_db.txt file into the Neo4j browser, and click `paste in editor`.
11. In the Browser command line, type *:style* at the beginning of the query, <br>
    so that the command line reads `:style ` with the styling content below it. 
12. Once entering the command, you should now be all set up to use/view the database.
---
### If you *have* Neo4j downloaded:
1. Open Neo4j Desktop and go to your choice of project folder.
2. In the top right, press `+ Add` to add file.
3. Select neo4j.dump from the supplied github files, and it should then show up in the "files" section.
4. To the right of neo4j.dump press the `...` button, and select `Create new DBMS from dump`.
   - Make sure your new database's Neo4j version matches the Neo4j version of the dump file.
5. Drag and drop the Style_db.txt file into the Neo4j browser, and click `paste in editor`.
6. In the Browser command line, type *:style* at the beginning of the query, <br>
    so that the command line reads `:style ` with the styling content below it.
7. After entering the command, you should be all set up to use/view the database.
   
