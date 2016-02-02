This is a python program written to launch a webpage that allows a login user to create, update, and delete.  Any user without login can only read the posted categories and their respective items.  User can login the site using Google account.  This program uses bootstrap class for styling and javascript, and jquery for ajax.

-Files
catalog/
|---application.py
|---client_secrets.json
|---database_setup.py
|---initialcatalogdatasetup.py
|---README.md
|---templates/
|-------------catalog.html
|-------------catalogitem.html
|-------------deletecatalogitem.html
|-------------editcatalogitem.html
|-------------header.html
|-------------main.html
|-------------newcatalogitem.html

- How to run the program
1) put all the above files in the respective folder mentioned above
2) launch a vagrant terminal
3) change directory to this folder
4) run command 'python database_setup.py' to get the database created
5) run command 'python initialcatalogdatasetup.py' to get the initial category dummy data inserted into database
6) run command 'python application.py' to launch the program
7) in a browser, type "http://localhost:5000" to start