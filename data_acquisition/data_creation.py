from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Boolean, Numeric
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

import os
from data_acquisition.data_reader import read_json_file

from datetime import datetime
import json
import re

basedir = os.path.abspath(os.path.dirname(__file__)).replace('data_acquisition', '')
base = declarative_base()
engine = create_engine('sqlite:///'+os.path.join(basedir, 'database.sqlite'), echo=False)

class DataCreating():    

    class CVE(base):
        
        __tablename__ = 'cve'

        # id = Column('id', Integer, primary_key=True, autoincrement=True)
        cve_id = Column('cve_id', String, primary_key=True)
        description = Column('description', String, unique=False)
        published_date = Column('published_date', DateTime, unique=False)
        last_modified = Column('last_modified', DateTime, unique=False)        
        cpes_related = relationship('CPE', back_populates="cpe_related")


        def __init__(self, cve_id, descrition, published_date, last_modified):
            
            self.cve_id = cve_id
            self.description = descrition
            self.published_date = published_date
            self.last_modified = last_modified            


    # One to One with CVE
    class CVSSV3(base):

        __tablename__ = 'cvssv3'

        id_cvssv3 = Column('id', Integer, primary_key=True, autoincrement=True)
        id_cve = Column('cve_id', String, ForeignKey('cve.cve_id'))
        version = Column('version', String)
        vector_string = Column('vector_string', String)
        attack_vector = Column('attack_vector', String)
        cvss3_score =  Column('cvss3_score', Numeric, unique=False)

        def __init__(self, id_cve, version, vector_string, attack_vector, cvss3_score):
            
            self.id_cve = id_cve
            self.version = version
            self.vector_string = vector_string
            self.attack_vector = attack_vector
            self.cvss3_score = cvss3_score
                

    class CPE(base):

        __tablename__ = 'cpe'

        id_cpe = Column('id', Integer, primary_key=True, autoincrement=True)
        id_cve = Column('cve_id', String, ForeignKey('cve.cve_id'))
        vulnerable = Column('vulnerable', Boolean)
        cpe_23_uri = Column('cpe_23_uri', String)
        vendor = Column('vendor', String)
        product = Column('product', String)        
        cpe_related = relationship("CVE", back_populates="cpes_related")


        def __init__(self, id_cve, vulnerable, cpe_23_uri, vendor, product):
            
            self.id_cve = id_cve
            self.vulnerable = vulnerable
            self.cpe_23_uri = cpe_23_uri
            self.vendor = vendor
            self.product = product
            
    
    @classmethod
    def gererate_tables(cls) -> bool:                        
        try: base.metadata.create_all(bind=engine)            
        except: return False
        else: return True
        
    
    @classmethod
    def remove_database(cls):
        _path = os.path.join(basedir, 'database.sqlite')
        if os.path.exists(_path):
            os.remove(_path)

    @classmethod
    def __get_vendor_product(cls, cvssv3_uri:str) -> tuple:        
        _pattern = 'cpe:[0-9]{1}\.[0-9]{1}\:[a-zA-Z]\:'
        _match = re.search(_pattern, cvssv3_uri)
        values = cvssv3_uri.replace(_match.group(0), '').split(':')
        return (values[0], values[1])        
    

    @classmethod
    def cve_parser(cls, id_cve:str, cve_object:dict): 
        
        description = cve_object['cve']['description']['description_data'][0]['value']
        published_date = datetime.strptime(cve_object['publishedDate'], '%Y-%m-%dT%H:%MZ')
        last_modified = datetime.strptime(cve_object['lastModifiedDate'], '%Y-%m-%dT%H:%MZ')                
        cve_model = DataCreating.CVE(id_cve, description, published_date, last_modified)

        return cve_model

    
    @classmethod
    def cvssv3_parser(cls, id_cve:str, cve_object:dict): 
        
        try: version = cve_object['impact']['baseMetricV3']['cvssV3']['baseScore']
        except: version = None
        
        try: vector_string = cve_object['impact']['baseMetricV3']['cvssV3']['vectorString']
        except: vector_string = None

        try: attack_vector = cve_object['impact']['baseMetricV3']['cvssV3']['attackVector']
        except: attack_vector = None

        try: cvss3_score = cve_object['impact']['baseMetricV3']['cvssV3']['baseScore']
        except: cvss3_score = None

        cvssv3_model = DataCreating.CVSSV3(id_cve, version, vector_string, attack_vector, cvss3_score)
        
        return cvssv3_model



    @classmethod
    def cpe_parser(cls, id_cve:str ,cpe_info:dict): 
        
        vulnerable = cpe_info['vulnerable']
        cpe_23_uri = cpe_info['cpe23Uri']
        vendor_product = cls.__get_vendor_product(cpe_info['cpe23Uri'])
        vendor = vendor_product[0]
        product = vendor_product[1]

        cpe_model = cls.CPE(id_cve, vulnerable, cpe_23_uri, vendor, product)
        return cpe_model


    @classmethod
    def get_cpes(cls,  id_cve:str, cve_object:dict) -> list:        
        cpe_objects = []

        cpe_nodes = cve_object['configurations']['nodes']          
        if not len(cpe_nodes): return cpe_objects            

        for node in cpe_nodes:
            if 'children' in node:
                for child in node['children']:
                    for cpe_match in child['cpe_match']:
                        cpe_objects.append(cls.cpe_parser(id_cve, cpe_match))
            else:
                for cpe_match in node['cpe_match']:
                    cpe_objects.append(cls.cpe_parser(id_cve, cpe_match))

        
        return cpe_objects


def populate_database():
    

    if os.path.exists(os.path.join(basedir, 'database.sqlite')):return

    DataCreating.remove_database()
    DataCreating.gererate_tables()

    Session = sessionmaker(bind=engine)
    session = Session()
    data = read_json_file(basedir, 'data.json')

    
    for cve_object in data:
        
        cve_id = cve_object['cve']['CVE_data_meta']['ID']
        cve_model = DataCreating.cve_parser(cve_id, cve_object)
        session.add(cve_model)
        
        cvssv3_model = DataCreating.cvssv3_parser(cve_id, cve_object)
        session.add(cvssv3_model)
        
        for cpe_model in DataCreating.get_cpes(cve_id, cve_object):
            session.add(cpe_model)
                        
    session.commit()
    session.close()

    

