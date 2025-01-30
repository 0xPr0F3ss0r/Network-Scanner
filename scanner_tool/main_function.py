import sys
import time
import socket
import nmap3
from threading import Thread
from alive_progress import alive_bar
import requests

# define class for main functions
class main_functions: 
    one_host = False
    domaine =True
    port= 0
    data = ""
    lists_of_hosts = []
    mydata = ""
    os_result = []
    version = ""
    scan= ""
    result_of_many_hosts = []
    list_host_domaine = []
    list_domaines = []
    def __init__(self,port):
        self.port = port
        self.adv_scanner = nmap3.Nmap()
        self.adv_scanner_technique = nmap3.NmapScanTechniques()
        self.adv_scanner_discover = nmap3.NmapHostDiscovery()
#taking domaine from user and add it to the list_domaines
    def TakeDomaine(self,domaine):
        self.list_domaines.append(domaine)
#get the ip address from domaine 
    def get_domaine_ip_add(self,domaine):
        try:
            result = requests.get(f'http://{domaine}', timeout=3)
            try:
                if result.status_code == 200:
                    try:
                        self.mydata = socket.gethostbyname(domaine)
                        return self.mydata
                    except Exception as e:
                        return False
                else:
                    return False
            except Exception as d:
                return False
        except Exception as s:
            return False
#our loading function
    def loading_animation(self,thread):
        with alive_bar(100, bar="bubbles", spinner="squares") as bar:
            while thread.is_alive():
                bar()  
                time.sleep(0.1)
        sys.stdout.write("\rScanning complete!      \n")
#scan with one host
    def One_host(self) :
        one_host = True
        host_type = input("what do u want to scan:\n [~]-ip address<IP> \n [~]-domaine<D> \nchose one: ")
        while str(host_type) != "IP" and str(host_type) != "D":
            print("invalid input, please enter just 'IP' or 'D' !!")
            time.sleep(2)
            host_type = input("what do u want to scan:\n [~]-ip address<IP> \n [~]-domaine<D> \nchose one: ")
        if str(host_type) == "IP":
            domaine = False
            self.lists_of_hosts.clear()
            hosts = input("*enter your target-ip address:")
            self.append(hosts)
        else:
            self.lists_of_hosts.clear()
            domaine = input("*enter your domaine :")
            self.TakeDomaine(domaine)
            self.get_domaine_ip_add(domaine)
            hosts = self.mydata
            self.lists_of_hosts.append(hosts)
#scan with multi host
    def Multi_host(self):
        one_host =False
        host_type = input("what do u want to scan:\n [~]-ip address<IP> \n [~]-domaine<D> \nchose one: ")
        while str(host_type) != "IP" and str(host_type) != "D":
            print("invalid input, enter just 'D' or 'IP' " )
            time.sleep(2)
            host_type = input("what do u want to scan:\n [~]-ip address<IP> \n [~]-domaine<D> \nchose one: ")
        if str(host_type) == "IP":
            self.lists_of_hosts.clear()
            number_of_hosts = input("number of hosts you want to scan: ")
            for number_host in range(1,int(number_of_hosts)+1):
                hosts = input(f"*enter your target-ip address number<{number_host}>:")
                self.lists_of_hosts.append(hosts)
        else:
            self.lists_of_hosts.clear()
            number_of_domaine = input("number of domaine you want to scan: ")
            while  not str(number_of_domaine).isnumeric():
                print("invalid input,enter just numeric numbers")
                time.sleep(2)
                number_of_domaine = input("number of domaine you want to scan: ")
            for number_host in range(1,int(number_of_domaine)+1):
                domaine = input(f"*enter your target-domaine number<{number_host}>:")
                while self.get_domaine_ip_add(domaine) == False:
                    print("invalid Domaine, Try a Valid Domaine")
                    domaine = input(f"*enter your target-domaine number<{number_host}>:")
                    self.get_domaine_ip_add(domaine)
                self.TakeDomaine(domaine)
                hosts = self.mydata
                self.lists_of_hosts.append(hosts)
                self.list_host_domaine.append(domaine)
#scan top ports with list of hosts as arguments
    def scan_top_ports(self,Lists_of_hosts):
        for host in range(len(Lists_of_hosts)):
            self.result_of_many_hosts.append(self.adv_scanner.scan_top_ports(Lists_of_hosts[host]))
#scan domaine using dns brute technique
    def scan_dns_brute(self,list_domaines):
        for host_domaine in range(len(list_domaines)):
            result = self.adv_scanner.nmap_dns_brute_script(list_domaines[host_domaine])
            self.result_of_many_hosts.append(result) 
#scan host to get the os running on his device
    def scan_os_detection(self,Lists_of_hosts):
        for host in range(len(Lists_of_hosts)):
            self.result_of_many_hosts.append(self.adv_scanner.nmap_os_detection(Lists_of_hosts[host]))
#scan host to get version of service running on his device
    def  scan_version_detection(self,Lists_of_hosts):
        for host in range(len(Lists_of_hosts)):
            result = self.adv_scanner.nmap_version_detection(Lists_of_hosts[host])
            self.result_of_many_hosts.append(result)
    def scan_nmap_get_version(self):
            self.result_of_many_hosts.append(self.adv_scanner.nmap_version())
    def fin_scan(self,Lists_of_hosts):
        for host in range(len(Lists_of_hosts)):
            self.result_of_many_hosts.append(self.adv_scanner_technique.nmap_fin_scan(Lists_of_hosts[host]))
    def idle_scan(self,Lists_of_hosts):
        for host in range(len(Lists_of_hosts)):
            self.result_of_many_hosts.append(self.adv_scanner_technique.nmap_idle_scan(Lists_of_hosts[host]))
    def ping_scan(self,Lists_of_hosts):
        for host in range(len(Lists_of_hosts)):
            self.result_of_many_hosts.append(self.adv_scanner_technique.nmap_ping_scan(Lists_of_hosts[host]))
    def syn_scan(self,Lists_of_hosts):
        for host in range(len(Lists_of_hosts)):
            self.result_of_many_hosts.append(self.adv_scanner_technique.nmap_syn_scan(Lists_of_hosts[host]))
    def tcp_scan(self,Lists_of_hosts):
        for host in range(len(Lists_of_hosts)):
            self.result_of_many_hosts.append(self.adv_scanner_technique.nmap_tcp_scan(Lists_of_hosts[host]))
    def udp_scan(self,Lists_of_hosts):
        for host in range(len(Lists_of_hosts)):
            self.result_of_many_hosts.append(self.adv_scanner_technique.nmap_udp_scan(Lists_of_hosts[host]))
    def port_scan_only(self,Lists_of_hosts):
        for host in range(len(Lists_of_hosts)):
            self.result_of_many_hosts.append(self.adv_scanner_discover.nmap_portscan_only(Lists_of_hosts[host]))
    def no_port_scan(self,Lists_of_hosts):
        for host in range(len(Lists_of_hosts)):
            self.result_of_many_hosts.append(self.adv_scanner_discover.nmap_no_portscan(Lists_of_hosts[host]))
    def arp_discover_scan(self,Lists_of_hosts):
        for host in range(len(Lists_of_hosts)):
            self.result_of_many_hosts.append(self.adv_scanner_discover.nmap_arp_discovery(Lists_of_hosts[host]))
    def disable_dns_scan(self,Lists_of_hosts):
        for host in range(len(Lists_of_hosts)):
            self.result_of_many_hosts.append(self.adv_scanner_discover.nmap_disable_dns(Lists_of_hosts[host]))
    def command_line(self,Lists_of_hosts,args):
        for host in range(len(Lists_of_hosts)):
            self.result_of_many_hosts.append(self.adv_scanner_discover.scan_top_ports(Lists_of_hosts[host], args=str(args)))
#scan host to get any vulnerabilities found
    def scan_vuln(self,Lists_of_hosts,argument):
        if str(argument) == "":
            for host in range(len(Lists_of_hosts)):
                self.result_of_many_hosts.append(self.adv_scanner.scan_top_ports(Lists_of_hosts[host], args="--script vulners --script-args mincvss+5.0"))
        else:
            for host in range(len(Lists_of_hosts)):
                self.result_of_many_hosts.append(self.adv_scanner.scan_top_ports(Lists_of_hosts[host], args=argument))
#loading functions used to create thread and scan all the host available with nice banner or what ever u called it in the same time
    def loading_scan_top_ports(self,lists_of_hosts):
        thread = Thread(target=self.scan_top_ports,args=(lists_of_hosts,))
        thread.start()
        self.loading_animation(thread)
       
    def loading_scan_dns_brute(self,list_host_domaine):
        thread = Thread(target=self.scan_dns_brute,args=(list_host_domaine,))
        thread.start()
        self.loading_animation(thread)
            
    def loading_scan_os_detection(self,lists_of_hosts):
        thread = Thread(target=self.scan_os_detection,args=(lists_of_hosts,))
        thread.start()
        self.loading_animation(thread)
    def loading_scan_version_detection(self,lists_of_hosts):
        thread = Thread(target=self.scan_version_detection,args=(lists_of_hosts,))
        thread.start()
        self.loading_animation(thread)
    def loading_nmap_get_version(self):
        thread = Thread(target=self.scan_nmap_get_version)
        thread.start()
        self.loading_animation(thread)
    def loading_subnet_scan(self, lists_of_hosts):
        thread = Thread(target=self.subnet_scan, args=(lists_of_hosts,))
        thread.start()
        self.loading_animation(thread)

    def loading_fin_scan(self, lists_of_hosts):
        thread = Thread(target=self.fin_scan, args=(lists_of_hosts,))
        thread.start()
        self.loading_animation(thread)

    def loading_idle_scan(self, lists_of_hosts):
        thread = Thread(target=self.idle_scan, args=(lists_of_hosts,))
        thread.start()
        self.loading_animation(thread)

    def loading_ping_scan(self, lists_of_hosts):
        thread = Thread(target=self.ping_scan, args=(lists_of_hosts,))
        thread.start()
        self.loading_animation(thread)

    def loading_syn_scan(self, lists_of_hosts):
        thread = Thread(target=self.syn_scan, args=(lists_of_hosts,))
        thread.start()
        self.loading_animation(thread)

    def loading_tcp_scan(self, lists_of_hosts):
        thread = Thread(target=self.tcp_scan, args=(lists_of_hosts,))
        thread.start()
        self.loading_animation(thread)

    def loading_udp_scan(self, lists_of_hosts):
        thread = Thread(target=self.udp_scan, args=(lists_of_hosts,))
        thread.start()
        self.loading_animation(thread)

    def loading_port_scan_only(self, lists_of_hosts):
        thread = Thread(target=self.port_scan_only, args=(lists_of_hosts,))
        thread.start()
        self.loading_animation(thread)

    def loading_no_port_scan(self, lists_of_hosts):
        thread = Thread(target=self.no_port_scan, args=(lists_of_hosts,))
        thread.start()
        self.loading_animation(thread)

    def loading_arp_discover_scan(self, lists_of_hosts):
        thread = Thread(target=self.arp_discover_scan, args=(lists_of_hosts,))
        thread.start()
        self.loading_animation(thread)

    def loading_disable_dns_scan(self, lists_of_hosts):
        thread = Thread(target=self.disable_dns_scan, args=(lists_of_hosts,))
        thread.start()
        self.loading_animation(thread)

    def loading_command_line(self, lists_of_hosts, args):
        thread = Thread(target=self.command_line, args=(lists_of_hosts, args))
        thread.start()
        self.loading_animation(thread)

    def loading_scan_vuln(self, lists_of_hosts):
        thread = ""
        arg = input("ADD argument to scan if you want(Y,N): ")
        if str(arg)=="N":
            thread = Thread(target=self.scan_vuln, args=(lists_of_hosts,"--script=default"))
        else:
            argument = str(input("ADD your arguments: "))
            thread = Thread(target=self.scan_vuln, args=(lists_of_hosts,argument))
        thread.start()
        self.loading_animation(thread)
#scan_number of scan used to start scan of any option that user can chose 
    def scan_1(self):
        for host_scan in range(len(self.lists_of_hosts)):
            host = self.lists_of_hosts[host_scan]
            print(f"Start scanning top ports in <{host}>")
            self.loading_scan_top_ports(self.lists_of_hosts)
            time.sleep(2)
            print("-" * 100)
            result = self.result_of_many_hosts[host_scan]
            command = result.get('stats',{})
            total_hosts = ""
            ip_data = result.get(host, {})
            runtime = result.get('runtime', {})
            task_results = result.get('task_results', [])
            print("Start scanning at:", command.get('startstr', 'N/A'),"with",host)
            state = ip_data.get('state', {})
            ports = ip_data.get('ports', [])
            host_name = ip_data.get('hostname',[])
            if len(host_name) > 0:
                if self.domaine:
                    my_domaine = "({})".format(self.domaine)
                    print("hostname: ",host_name[0]['name'],my_domaine)
                else:
                    print("hostname:",host_name[0]['name'],"( )")
            print("HOST State:", state['state'] ,"•", " ","reason: ",state['reason'])
            try:
                task_result = ip_data.get('task_result', {})
                total_hosts = task_results[0]['extrainfo']
            except Exception as e:
                total_hosts = "no host found"
            print("total hosts:", total_hosts)
            if len(ports) > 0:
                try:
                    for port_number in range(len(ports)):
                        try:
                            version = ports[port_number]['service'].get("version","No Version Detected")
                        except Exception as e:
                            print("Error: {}".format(e))
                        print("port number: "," ", ports[port_number]['portid']," • ","service: ", " ",ports[port_number]['service']['name']," • ","state: "," ",ports[port_number]['state'], " • ","verion: "," ",version)
                except Exception as e:
                    print("error",e , "Try again please !!")
            else:
                print(f"ports: No port found for this host <{host}>")
    def scan_2(self):
        print("this scann can take many minutes to complete, please wait !!")
        for host_scan in range(0,len(self.list_domaines)):
            host = self.list_domaines[host_scan]
            print(f"Start scanning DNS brute force in <{host}>")
            self.loading_scan_dns_brute(self.list_domaines)
            time.sleep(2)
            print("-" * 100)
            if  self.one_host:
                    for result in range(len(self.result_of_many_hosts[host_scan])):
                        map_subdomaines = self.result_of_many_hosts[host_scan]
                        map_subdomaines_2 = map_subdomaines[result].get("hostname","no sub domaine found")
                        map_subdomaines_3 = map_subdomaines[result].get("address","no address found")
                        print("*" * 90)
                        print(f"subdomaine [{result}] : {map_subdomaines_2} , address [{result}] : {map_subdomaines_3}")
            else:
                [print("#"*120) for i in range(2)]
                for first_domaine in range(len(self.result_of_many_hosts[host_scan])):
                        map_subdomaines_first = self.result_of_many_hosts[host_scan]
                        map_subdomaines_first_2 = map_subdomaines_first[first_domaine].get("hostname","no sub domaine found")
                        map_subdomaines_first_3 = map_subdomaines_first[first_domaine].get("address","no address found")
                        print("*" * 90)
                        print(f"subdomaine [{first_domaine}] : {map_subdomaines_first_2} , address [{first_domaine}] : {map_subdomaines_first_3}\n")

    def scan_3(self):
        for host_scan in range(len(self.lists_of_hosts)):
            host = self.lists_of_hosts[host_scan]
            print(f"Start scanning OS detection in <{host}>")
            self.loading_scan_os_detection(self.lists_of_hosts)
        time.sleep(2)
        print("-" * 100)
        if len(self.result_of_many_hosts) ==0:
            print('error' ,self.result_of_many_hosts['msg'] )
        else:
            print('::',self.result_of_many_hosts[0]['msg'])
            try:
                hosts_found = self.result_of_many_hosts['task_results'][0]['extrainfo']
            except Exception as e:
                hosts_found = 0
            try:
                port_found = self.result_of_many_hosts['task_results'][2]['extrainfo']
            except Exception as e:
                port_found = 0
            print(f'{hosts_found} found for this scan with {port_found} found')
    def scan_4(self):
        for host_scan in range(len(self.lists_of_hosts)):
            host = self.lists_of_hosts[host_scan]
            print(f"Start scanning specific ports in <{host}> (Scan 4)")
            self.loading_scan_version_detection(self.lists_of_hosts)  
            time.sleep(2)
            print("-" * 100)
            result = self.result_of_many_hosts[host_scan]
            command = result.get('stats', {})
            total_hosts = ""
            ip_data = result.get(host, {})
            runtime = result.get('runtime', {})
            task_results = result.get('task_results', [])
            print("Start scanning at:", command.get('startstr', 'N/A'), "with", host)
            state = ip_data.get('state', {})
            ports = ip_data.get('ports', [])
            host_name = ip_data.get('hostname', [])
            if len(host_name) > 0:
                if self.domaine:
                    my_domaine = "({})".format(self.domaine)
                    print("hostname: ", host_name[0]['name'], my_domaine)
                else:
                    print("hostname:", host_name[0]['name'], "( )")
            print("HOST State:", state['state'], "•", " ", "reason: ", state['reason'])
            try:
                task_result = ip_data.get('task_result', {})
                total_hosts = task_results[0]['extrainfo']
            except Exception as e:
                total_hosts = "no host found"
            print("total hosts:", total_hosts)
            if len(ports) > 0:
                try:
                    for port_number in range(len(ports)):
                        try:
                            version = ports[port_number]['service'].get("version", "No Version Detected")
                        except Exception as e:
                            print("Error: {}".format(e))
                        print("port number: ", " ", ports[port_number]['portid'], " • ", "service: ", " ",
                              ports[port_number]['service']['name'], " • ", "state: ", " ", ports[port_number]['state'],
                              " • ", "version: ", " ", version)
                except Exception as e:
                    print("error", e, "Try again please !!")
            else:
                print(f"ports: No port found for this host <{host}>")
    def scan_5(self):
        print("Getting nmap version...")
        self.loading_nmap_get_version()
        time.sleep(2)
        print("-" * 100)
        nmap_version = self.result_of_many_hosts[0]['nmap']
        print("current nmap version is " , nmap_version)
    def scan_6(self):
        for host_scan in range(len(self.lists_of_hosts)):
            host = self.lists_of_hosts[host_scan]
            print(f"Start performing FIN scan in <{host}>")
            self.loading_fin_scan(self.lists_of_hosts)
            time.sleep(2)
            print("-" * 100)
            if len(self.result_of_many_hosts[host_scan]) <4:
                print('error' ,self.result_of_many_hosts[0]['msg'] )
            else:
                try:
                    hosts_found = self.result_of_many_hosts[host_scan]['task_results'][0]['extrainfo']
                except Exception as e:
                    hosts_found = 0
                try:
                    port_found = self.result_of_many_hosts[host_scan]['task_results'][2]['extrainfo']
                except Exception as e:
                    port_found = 0 
                try:
                    date = 'in' + self.result_of_many_hosts[host_scan].get('runtime').get('timestr')
                except Exception as e:
                    data = data
                print(f'{hosts_found} found for this scan with {port_found} found  {data}')
    def scan_7(self):
        for host_scan in range(len(self.lists_of_hosts)):
            host = self.lists_of_hosts[host_scan]
            print(f"Start performing idle scan in <{host}>")
            self.loading_idle_scan(self.lists_of_hosts)
            time.sleep(2)
            print("-" * 100)
            last_result = self.result_of_many_hosts[host_scan].get('task_results')[0].get('task')
            date = self.result_of_many_hosts[host_scan].get('runtime').get('timestr')
            print(f'{last_result} found for this scan in {date}')
    def scan_8(self):
        for host_scan in range(len(self.lists_of_hosts)):
            host = self.lists_of_hosts[host_scan]
            print(f"Start performing ping scan in <{host}>")
            self.loading_ping_scan(self.lists_of_hosts)
            time.sleep(2)
            print("-" * 100)
            last_result = self.result_of_many_hosts[host_scan].get('task_results')[0].get('extrainfo')
            date = self.result_of_many_hosts[host_scan].get('runtime').get('timestr')
            print(f'{last_result} found for this scan in {date}')
    def scan_9(self):
        for host_scan in range(len(self.lists_of_hosts)):
            host = self.lists_of_hosts[host_scan]
            print(f"Start performing SYN scan in <{host}>")
            self.loading_syn_scan(self.lists_of_hosts)
            time.sleep(2)
            print("-" * 100)
            if len(self.result_of_many_hosts[host_scan]) <4:
                print('error' ,self.result_of_many_hosts[host_scan]['msg'] )
            else:
                hosts_found = self.result_of_many_hosts[host_scan]['task_results'][0]['extrainfo']
                port_found = self.result_of_many_hosts[host_scan].get('task_results')[2].get('extrainfo')
                print(f'{hosts_found} found for this scan with {port_found} found')
    def scan_10(self):
        for host_scan in range(len(self.lists_of_hosts)):
            host = self.lists_of_hosts[host_scan]
            print(f"Start performing TCP scan in <{host}>")
            self.loading_tcp_scan(self.lists_of_hosts)
            time.sleep(2)
            print("-" * 100)
            last_result = self.result_of_many_hosts[host_scan].get('task_results')[0].get('task')
            date = self.result_of_many_hosts[host_scan].get('runtime').get('timestr')
            print(f'{last_result} found for this scan in {date}')
    def scan_11(self):
        for host_scan in range(len(self.lists_of_hosts)):
            host = self.lists_of_hosts[host_scan]
            print(f"Start performing UDP scan in <{host}>")
            self.loading_udp_scan(self.lists_of_hosts)
            time.sleep(2)
            print("-" * 100)
            if len(self.result_of_many_hosts[host_scan]) <4:
                error_message = self.result_of_many_hosts[host_scan]['msg']
                print('error' , error_message)
            else:
                try:
                    hosts_found = self.result_of_many_hosts[host_scan].get('task_results')[0].get('extrainfo')
                except Exception as e:
                    hosts_found = 0
                print(f'{hosts_found} found for this scan')
    def scan_12(self):
        for host_scan in range(len(self.lists_of_hosts)):
            host = self.lists_of_hosts[host_scan]
            print(f"Start performing port scan only in <{host}>")
            self.loading_port_scan_only(self.lists_of_hosts)
            time.sleep(2)
            print("-" * 100)
            print(self.result_of_many_hosts)
            result = self.result_of_many_hosts[host_scan]
            command = result.get('stats',{})
            total_hosts = ""
            ip_data = result.get(host, {})
            runtime = result.get('runtime', {})
            task_results = result.get('task_results', [])
            print("Start scanning at:", command.get('startstr', 'N/A'),"with",host)
            service = ip_data.get('service',{})
            if service.get('version'):
                version = service.get('version')
            version = "not found"
            state = ip_data.get('state', {})
            ports = ip_data.get('ports', [])
            host_name = ip_data.get('hostname',[])
            if len(host_name) > 0:
                print("hostname:",host_name[0]['name'])
            print("HOST State:", state['state'] ,"•", " ","reason: ",state['reason'])
            try:
                task_result = ip_data.get('task_result', {})
                total_hosts = task_results[0]['extrainfo']
            except Exception as e:
                total_hosts = "no host found"
            print("total hosts:", total_hosts)
            if len(ports) > 0:
                try:
                    for port_number in range(len(ports)):
                        print("port number: "," ", ports[port_number]['portid']," ","service", " ",ports[port_number]['service']['name']," ","state"," ",ports[port_number]['state']," ","version",version)
                except Exception as e:
                    print("error",e , "Try again please !!")
            else:
                print(f"ports: No port found for this host <{host}>")
    def scan_13(self):
        for host_scan in range(len(self.lists_of_hosts)):
            host = self.lists_of_hosts[host_scan]
            print(f"Start performing no port scan in <{host}>")
            self.loading_no_port_scan(self.lists_of_hosts)
            time.sleep(2)
            print("-" * 100)
            result = self.result_of_many_hosts[host_scan]
            ip_data = result.get(host, {})
            state = ip_data.get('state', {})
            task_results = result.get('task_results', [])
            host_name = ip_data.get('hostname',[])
            if len(host_name) > 0:
                print("hostname:",host_name[0]['name'])
            print("HOST State:", state['state'] ,"•", " ","reason: ",state['reason'])
            try:
                task_result = ip_data.get('task_result', {})
                total_hosts = task_results[0]['extrainfo']
            except Exception as e:
                total_hosts = "no host found"
            print("total hosts:", total_hosts)
    def scan_14(self):
        for host_scan in range(len(self.lists_of_hosts)):
            host = self.lists_of_hosts[host_scan]
            print(f"Start performing ARP discovery in <{host}>")
            self.loading_arp_discover_scan(self.lists_of_hosts)
            time.sleep(2)
            print("-" * 100)
            result = self.result_of_many_hosts[host_scan]
            command = result.get('stats',{})
            total_hosts = ""
            ip_data = result.get(host, {})
            runtime = result.get('runtime', {})
            task_results = result.get('task_results', [])
            print("Start scanning at:", command.get('startstr', 'N/A'),"with",host)
            state = ip_data.get('state', {})
            ports = ip_data.get('ports', [])
            host_name = ip_data.get('hostname',[])
            if len(host_name) > 0:
                hostname = host_name[0]['name']
                print("hostname:",hostname)
            print("HOST State:",state['state']  ,"•", " ","reason: ",state['reason'])
            try:
                task_result = ip_data.get('task_result', {})
                total_hosts = task_results[0]['extrainfo']
            except Exception as e:
                total_hosts = "no host found"
            print("total hosts:", total_hosts)
            if len(ports) > 0:
                try:
                    for port_number in range(len(ports)):
                        print("port number: "," ", ports[port_number]['portid']," ","service", " ",ports[port_number]['service']['name']," ","state"," ",ports[port_number]['state'])
                except Exception as e:
                    print("error",e , "Try again please !!")
            else:
                print(f"ports: No port found for this host <{host}>")
    def scan_15(self):
        for host_scan in range(len(self.lists_of_hosts)):
            host = self.lists_of_hosts[host_scan]
            print(f"Start performing DNS disabling in <{host}>")
            self.loading_disable_dns_scan(self.lists_of_hosts)
            time.sleep(2)
            print("-" * 100)
            result = self.result_of_many_hosts[host_scan]
            command = result.get('stats',{})
            total_hosts = ""
            ip_data = result.get(host, {})
            runtime = result.get('runtime', {})
            task_results = result.get('task_results', [])
            starting_time = command.get('startstr', 'N/A')
            print("Start scanning at:", starting_time,"with",host)
            state = ip_data.get('state', {})
            ports = ip_data.get('ports', [])
            print("HOST State:", state['state'])
            try:
                task_result = ip_data.get('task_result', {})
                total_hosts = task_results[0]['extrainfo']
            except Exception as e:
                total_hosts = "no host found"
            print("total hosts:", total_hosts)
            if len(ports) > 0:
                try:
                    for port_number in range(len(ports)):
                        print("port number: "," ", ports[port_number]['portid']," ","service", " ",ports[port_number]['service']['name']," ","state"," ",ports[port_number]['state'])
                except Exception as e:
                    print("error",e , "Try again please !!")
            else:
                print(f"ports: No port found for this host <{host}>")
    def scan_16(self):
        args = input("Enter additional nmap arguments: ")
        for host_scan in range(len(self.lists_of_hosts)):
            host = self.lists_of_hosts[host_scan]
            print(f"Start scanning with custom command in <{host}>")
            self.loading_command_line(self.lists_of_hosts, args)
            time.sleep(2)
            print("-" * 100)
            result = self.result_of_many_hosts[host_scan]
            command = result.get('stats',{})
            total_hosts = ""
            ip_data = result.get(host, {})
            runtime = result.get('runtime', {})
            task_results = result.get('task_results', [])
            print("Start scanning at:", command.get('startstr', 'N/A'),"with",host)
            state = ip_data.get('state', {})
            ports = ip_data.get('ports', [])
            print("HOST State:", state['state'])
            try:
                task_result = ip_data.get('task_result', {})
                total_hosts = task_results[0]['extrainfo']
            except Exception as e:
                total_hosts = "no host found"
            print("total hosts:", total_hosts)
            if len(ports) > 0:
                try:
                    for port_number in range(len(ports)):
                        print("port number: "," ", ports[port_number]['portid']," ","service: ", " ",ports[port_number]['service']['name']," ","state: "," ",ports[port_number]['state'])
                except Exception as e:
                    print("error",e , "Try again please !!")
            else:
                print(f"ports: No port found for this host <{host}>")
    def scan_17(self):
        for host_scan in range(len(self.lists_of_hosts)):
            host = self.lists_of_hosts[host_scan]
            print(f"Start scanning vulnerabilities in <{host}>")
            self.loading_scan_vuln(self.lists_of_hosts)
            time.sleep(2)
            print("-" * 100)
            result = self.result_of_many_hosts[host_scan]
            command = result.get('stats',{})
            total_hosts = ""
            ip_data = result.get(host, {})
            runtime = result.get('runtime', {})
            task_results = result.get('task_results', [])
            print("Start scanning at:", command.get('startstr', 'N/A'),"with",host)
            state = ip_data.get('state', {})
            ports = ip_data.get('ports', [])
            host_name = ip_data.get('hostname',[])
            if len(host_name) > 0:
                print("hostname:",host_name[0]['name'])
            print("HOST State:", state['state'] ,"•", " ","reason: ",state['reason'])
            try:
                task_result = ip_data.get('task_result', {})
                total_hosts = task_results[0]['extrainfo']
            except Exception as e:
                total_hosts = "no host found"
            print("total hosts:", total_hosts)
            if len(ports) > 0:
                try:
                    for port_number in range(len(ports)):
                        print("port number: "," ", ports[port_number]['portid'],"&","service: "," ",ports[port_number]['service']['name'],"&","state: "," ",ports[port_number]['state'])
                        for vuln_test in ports[port_number]['scripts']:
                            print("vulnerabilities: ","Test for: ",vuln_test["name"] ,"&", "result_found: ",vuln_test['raw'])
                except Exception as e:
                    print("error",e , "Try again please !!")
            else:
                print(f"ports: No port found for this host <{host}>")
            task_result = result.get("task_results",[])
            if len(task_results) > 0:
                for task in range (len(task_results)):
                    task = task_results[task].get("task")