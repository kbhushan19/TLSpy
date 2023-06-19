import os, sys,re,json
from datetime import *

import traceback
#pip install xmltodict
import xmltodict

Current_Date = datetime.today().strftime('%d%b%Y')
Current_Directory = os.path.dirname(sys.argv[0])
Current_Directory = os.path.abspath(Current_Directory)

def cipher_suite(Input_List,Output_File=f"{Current_Directory}/Outputs/temp.csv",Output_format='csv'):
    temp_outputpath = f"{Current_Directory}/Outputs/Temp/temp.xml"
    Cipher_List=[]
    try:
        os.makedirs(os.path.dirname(temp_outputpath))
    except:
        pass
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
    print(Cipher_List[0],'\n\n',len(Cipher_List),"\n\n",Cipher_List)

if __name__=='__main__':
    cipher_suite([{'Domain':'google.com','IP':'142.250.192.238'}])


'''
                for x in fil.read().splitlines():
                    x = x.strip()
                    x = x.replace('|', '')
                    x = x.strip()
                    if 'Nmap scan report for' in x:
                        Request_Domain = x.rstrip().split(' ')[4]
                        print(Request_Domain)
                    if re.search('^\d+\/\w+', x):
                        y = re.sub(' +', ' ', x)
                        y = y.split(' ')
                        Port = str(y[0])
                        State = str(y[1])
                        Service = str(y[2])
                        Temp = list(y[3:])
                        Version = ""
                        for z in Temp:
                            Version = Version + " " + z
                            Version = Version.lstrip()

                        print("Port = " + Port)
                        print("State = " + State)
                        print("Service = " + Service)
                        #print("Version = " + Version)
                    print(Cipher_Flag)
                    if Cipher_Flag:
                        if x != 'compressors:':
                            Cipher_List.append(x)

                        if 'compressors:' == x:
                            Cipher_Flag = False
                            Error_List = Cipher_List
                            Cipher_List = []

                    if x == 'ciphers:':
                        Cipher_Flag = True

                    if ("sslv" in x.lower() and ":" in x.lower()) or ("tlsv" in x.lower() and ":" in x.lower()):
                        SSL_Version = x.strip().replace(":" , "")
                        print("SSL_Version = " + SSL_Version )

                    if Cipher_Flag:
                        #print("False..")
                        if x == 'warnings:':
                            #print("WARNING!!!!!")
                            for Cipher in Error_List:
                                Cipher = Cipher.rstrip()
                                if '- C' in Cipher:
                                    Cipher=Cipher.replace('- C','')
                                    Vulnerable = "YES"
                                    Alert_Flag = 'MEDIUM'
                                elif '- B' in Cipher:
                                    Cipher = Cipher.replace('- B', '')
                                    Vulnerable = "YES"
                                    Alert_Flag = "LOW"
                                elif '- D' in Cipher:
                                    Cipher = Cipher.replace('- D', '')
                                    Vulnerable = "YES"
                                    Alert_Flag = "HIGH"
                                elif '- A' in Cipher:
                                    Cipher = Cipher.replace('- A', '')
                                    Vulnerable = "NO"
                                    Alert_Flag = "LOW"
                                elif '- F' in Cipher:
                                    Cipher = Cipher.replace('- F', '')
                                    Vulnerable = "YES"
                                    Alert_Flag = "HIGH"
                                elif '- E' in Cipher:
                                    Cipher = Cipher.replace('- E', '')
                                    Vulnerable = "YES"
                                    Alert_Flag = "HIGH"
                                else:
                                    Vulnerable = "YES"
                                    Alert_Flag = 'MEDIUM'

                                data = {}#with open(Output_File, 'a') as f:
                                data['Cipher'],data['Port_Number'],data['ip'],data['Service'],data['Version'],data['Request_Domain'],data['Vulnerable'],data['Alert_Flag'] = Cipher.strip(), Port_Number, ip.rstrip(), Service , SSL_Version, Request_Domain,Vulnerable, Alert_Flag
                                print(data)
'''
