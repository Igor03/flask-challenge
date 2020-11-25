## Data Engineering Case


The purpose of this task is to show us your coding-skills, knowledge of database design, and how to use the database efficiently. 

Your task is to enter data from the `data.json` file into an SQLite database, and make the data available through an API. The json-file contains 1000 randomly sampled CVEs' from 2019, with information related to each CVE.


### Specifications:

#### API

1. An endpoint `/cpe/{vendor}/{product}` exists that returns a list of all CVEs related to that particular CPE.
2. An endpoint `/cve/{cve_id}` exists that returns a CVE with its corresponding CVSS3, CPEs, description, and dates. 
3. The API should be implemented using Flask.

#### Database 

The json contains lots of information that we are not interested in, and to narrow the scope of the case only this information should be entered into the database. 

1. All CVEs', with its description and related dates.
2. All CPEs' excluding version data. CPEs' can have different configurations and operators, but you should regard all CPEs' as directly affected by a CVE, so don't mind the operator/children structure. 
3. The CVSS3 score related to each CVE. 
4. This should be implemented using SqlAlchemy.

The database should be an SQLite database. 


#### Other

You may use any other external/OSS dependencies, but keep in mind to specify a requirements.txt file or use pipenv. The project will be tested in a Linux environment. You do not need to make it "production ready" with docerization, nginx, or anything like that. I will profile at what speed you can enter the data into the database. We suggest you spend about 5-6 hours on the task but may take longer if you are unexperienced to any of the concepts. 

Good luck!
