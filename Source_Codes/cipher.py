import os, sys,re,json
from datetime import *

import traceback
#pip install xmltodict
import xmltodict

Current_Date = datetime.today().strftime('%d%b%Y')
Current_Directory = os.path.dirname(sys.argv[0])
Current_Directory = os.path.abspath(Current_Directory)

from output_writer import output_writer

def cipher_suite(Input_List,Output_File=f"{Current_Directory}/Outputs/temp.csv",Output_format='csv'):
    temp_outputpath = f"{Current_Directory}/Outputs/Temp/temp.xml"
    Cipher_List=[]
    os.makedirs(os.path.dirname(temp_outputpath),exist_ok=True)
    
    port_list = [443]
    for item in Input_List:
        ip = item['IP']
        for Port_Number in port_list:
            data={"Domain":item['Domain'],"IP":ip,'Port':Port_Number}
            print(f"Checking for {ip}:{Port_Number}")
            os.system('nmap -sV --script ssl-enum-ciphers -p %s %s -oX %s' % (Port_Number, ip, temp_outputpath))
            with open(temp_outputpath) as fil:
                json_obj = xmltodict.parse(fil.read())
                for cipher_item in json_obj['nmaprun']['host']['ports']['port']['script']:
                    if cipher_item['@id'] == "ssl-enum-ciphers":
                        for  version in cipher_item['table']:
                            Version = version['@key']
                            for cipher in version['table']:
                                #print(cipher)
                                if cipher['@key']=='ciphers':
                                    for suites in cipher['table']:
                                        print(suites)
                                        # {'elem': [{'@key': 'name', '#text': 'TLS_RSA_WITH_3DES_EDE_CBC_SHA'}, {'@key': 'kex_info', '#text': 'rsa 2048'}, {'@key': 'strength', '#text': 'C'}]}
                                        data['Cipher_Suite']=suites['elem'][0]['#text']
                                        data['Key_Info']=suites['elem'][1]['#text']
                                        data['strength']=suites['elem'][2]['#text']

                                        Cipher_List.append(data.copy())
                # protocol = ['nmaprun']['host']['ports']['port']['@protocol']
                #service = ['nmaprun']['host']['ports']['port']['service']['@name']
                # cipher = ['nmaprun']['host']['ports']['port']['script']["@id":"ssl-enum-ciphers"]
    #print(Cipher_List[0],'\n\n',len(Cipher_List),"\n\n",Cipher_List)
    output_writer(Cipher_List,Output_File,Output_format)


if __name__=='__main__':
    cipher_suite([{'Domain':'google.com','IP':'142.250.192.238'}],Output_format='json')
