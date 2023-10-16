import argparse
import nmap


#argparser
parser = argparse.ArgumentParser(description="\n\n\n\n -i ipaddress",
                                 formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument("-i", "--ip", help="ipaddress")
args = parser.parse_args()
config = vars(args)

#nmap
ip = args.ip
nm = nmap.PortScanner()
nm.scan(arguments='-sS -A',hosts=ip)

for host in nm.all_hosts():
    print('----------------------------------------------------')
    print('Host : %s (%s)' % (host, nm[host].hostname()))
    print('State : %s' % nm[host].state())
    for proto in nm[host].all_protocols():
        print('----------')
        print('Protocol : %s' % proto)

        lport = nm[host][proto].keys()
        #lport.sort()
        for port in lport:
            print ('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))
            print('port : %s\tservice : %s' % (port, nm[host][proto][port]['name']))
