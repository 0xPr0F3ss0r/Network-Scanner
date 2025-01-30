from turtle import clearscreen
import time
from scanner_tool.main_function import main_functions
from scanner_tool.sub_functions import PrintBanner, cleanScreen , GetPortName
port= 0
#create obj of class that contains our main functions
main_functions_1 = main_functions(port)
#banner of tool
PrintBanner()
how_many_hosts = input("How many hosts you want to scan:\n [~]-<1> \n [~]-<more> \nchose one: ")
while str(how_many_hosts) != "1" and str(how_many_hosts) != 'more':
    print("invalid input, please enter just '1' or 'more' !!")
    time.sleep(2)
    how_many_hosts = input("How many hosts you want to scan:\n [~]-<1> \n [~]-<more> \nchose one: ")
#function to clear screen when scan start
cleanScreen()
if str(how_many_hosts) == "1":
    one_host = True
    main_functions_1.One_host()
elif str(how_many_hosts) == "more":
    main_functions_1.Multi_host()
scan_type = input("what type of scan do u want:\n\n type scan : \n 1-scan top port \n 2-scan dns brute(must be root) \n 3-scan os detection(must be root)\n 4-scan version detection\n 5-get nmap version  \n\n scan technique: \n 6-fin scan \n 7-idle scan\n 8-ping scan\n 9-syn scan(must be root)\n 10-tcp scan \n 11-udp scan \n\n scan with host discover: \n 12-port scan only\n 13-no port scan\n 14-scan arp discovery\n 15-disable dns\n 16-scan top ports with specified command\n 17-scan vulnerabilities\n your choice:  ")
cleanScreen()
#each number represent options that can user 
if str(scan_type) == "1":
    main_functions_1.scan_1()
elif str(scan_type) == "2":
    main_functions_1.scan_2()
elif str(scan_type) == "3":
    main_functions_1.scan_3()
elif str(scan_type) == "4":
    main_functions_1.scan_4()
elif str(scan_type) == "5":
    main_functions_1.scan_5()
elif str(scan_type) == "6":
    main_functions_1.scan_6()
elif str(scan_type) == "7":
    main_functions_1.scan_7()
elif str(scan_type) == "8":
    main_functions_1.scan_8()
elif str(scan_type) == "9":
    main_functions_1.scan_9()
elif str(scan_type) == "10":
    main_functions_1.scan_10()
elif str(scan_type) == "11":
    main_functions_1.scan_11()
elif str(scan_type) == "12":
    main_functions_1.scan_12()
elif str(scan_type) == "13":
    main_functions_1.scan_13()
elif str(scan_type) == "14":
    main_functions_1.scan_14()
elif str(scan_type) == "15":
    main_functions_1.scan_15()
elif str(scan_type) == "16":
    main_functions_1.scan_16()
elif str(scan_type) == "17":
    main_functions_1.scan_17()    
else:
    print("Invalid scan type. Please select a valid option.")




