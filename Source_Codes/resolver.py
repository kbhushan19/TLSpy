from dns_resolver import resolve_ipv4, resolve_ipv6



def get_IP(Input_List):
    return_list = []
    for domain in Input_List:
        data={'Domain':domain}
        try:
            result = resolve_ipv4(domain)

            ip=str(result[0])
            data['IP'] = ip
            return_list.append(data)
            continue
        except:
            print(traceback.format_exc())
            try:
                result = resolve_ipv6(domain)
                ip=str(result[0])
                data['IP'] = ip
                return_list.append(data)
            except:
                data['IP'] = "NULL"
                return_list.append(data)
    return return_list

def get_domain(Input_List):
    return_list = []
    for ip in Input_List:
        data={'Domain':"Domain","IP":ip}
        return_list.append(data)
    return return_list
