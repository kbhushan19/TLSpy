
import os, sys,re
from datetime import *

import traceback
#pip install xmltodict
import xmltodict

import argparse
import json



# ----------------- Important Variable initialization ---------------#

Current_Date = datetime.today().strftime('%d%b%Y')
Current_Directory = os.path.dirname(sys.argv[0])
Current_Directory = os.path.abspath(Current_Directory)



sys.path.insert(1,f"{Current_Directory}/Source_Codes/")

from resolver import get_domain,get_IP


from cipher import cipher_suite




class MyParser(argparse.ArgumentParser):
    def error(self, message):
        sys.stderr.write('error: %s\n' % message)
        self.print_help()
        sys.exit(2)

parser = MyParser()
input_group = parser.add_mutually_exclusive_group(required=True)
input_group.add_argument("-iL", "--input_list", help="Pass input as a CLI.")
input_group.add_argument("-if", "--input_file", help="Pass inputs as a File.")

input_type_group = parser.add_mutually_exclusive_group(required=True)
input_type_group.add_argument("-d", "--domain",action='store_true' ,help="To check for domain.")
input_type_group.add_argument("-ip", "--IP",action='store_true' , help="To check for IPv4 & IPv6.")

output_format_group = parser.add_mutually_exclusive_group()#required=True)
output_format_group.add_argument( "--csv" ,action='store_true',help="To store the O/P as CSV file.")
output_format_group.add_argument( "--json" ,action='store_true', help="To store the O/P as JSON file.")

parser.add_argument("-o", "--Output_File", help="File Path to store the Output (Default: Outputs folder as CSV).",)#required=True)

args = parser.parse_args()

Input_List = []

if args.input_list:
    Input_List = [args.input_list.strip()]

if args.input_file:
    try:
        with open(args.input_file.strip(),'r') as fil:
            Input_List = fil.read().splitlines()
    except Exception as e:
        print(e)

if not Input_List:
    print(f"\n\n--------------------------\nDidn't Receive any Input.\n\nQuitting.\n")
    sys.exit()

if args.domain:
    Input_List = get_IP(Input_List)
if args.IP:
    Input_List = get_domain(Input_List)

if args.Output_File:
    if args.csv:
        Output_File= args.Output_File
        Output_format='csv'
    elif args.json:
        Output_File= args.Output_File
        Output_format='json'
    else:
        print(f"\n\nOutput File format is not defined.\n\n\nQuitting")
        sys.exit()
else:
    Output_File= f"{Current_Directory}/Outputs/temp.csv"
    Output_format='csv'


cipher_suite(Input_List)#,Output_File,Output_format)

