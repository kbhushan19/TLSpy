import json,csv,os
def csv_writer(Cipher_List,Output_File):
    count = 0
    with open(Output_File,'a') as fil:
        csv_writer = csv.writer(fil)
        for lines in Cipher_List:
            if count==0:
                header = lines.keys()
                csv_writer.writerow(header)
                count=1
            csv_writer.writerow(lines.values())

def json_writer(Cipher_List,Output_File):
    with open(Output_File,'a') as fil:
        for lines in Cipher_List:
            json.dump(lines,fil)
            fil.write("\n")


def output_writer(Cipher_List,Output_File,Output_format):
    os.makedirs(os.path.dirname(Output_File),exist_ok=True)
    if os.path.exists(Output_File):
        os.remove(Output_File)
    if Output_format=='csv':
        csv_writer(Cipher_List,Output_File)
    elif Output_format=='json':
        json_writer(Cipher_List,Output_File)
    else:
        print("File Format is not recognized")
    print(f"\n\n  [+] Output : {Output_File}\n\n")

if __name__=='__main__':
    print("NADA")
