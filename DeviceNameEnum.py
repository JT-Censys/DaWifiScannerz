

#Imports
import subprocess, sys, datetime, time, os, socket

def Clear(Type):
    match Type:
        case 1:
            con.write("\r                                                                                ")
        case 2:
            os.system("clear")
        case _:
            os.system("clear")

def IsValidIpToUse(ip):
    if ip in CurrentIPs.keys():
        if TwoHoursPassed(CurrentIPs[ip]):
            return True
        else:
            return False
    else:
        return True

def TwoHoursPassed(value):
    if value < (value + datetime.timedelta(minutes=30)): return False
    return True

def GetLocalAddress(dik):
    TerminalSpam(dik,"Aquiring Local Address")
    IPinet = subprocess.check_output("ip -o -f inet addr show enp1s0 | awk \'/scope global/ {print $4}\'", shell=True).decode("utf-8").replace('\n','')
    TerminalSpam(dik,f"Aquired {IPinet}")
    return IPinet

def TerminalSpam(dik,CP):
    Clear(2)
    print(f'Currently: {CP}')
    for key, value in sorted(dik.items(), key=lambda item: socket.inet_aton(item[0])):
        if value != "":
            key = str(key).replace("\n","")
            value = str(value).replace("\n","")
            print(f'{key}: {value}')

#Variables
dik = {}
i = 1
t = 0
l = 0
CurrentIPs = {}
IPsToScan = []
closed = []
k = 1
y = 0
con = sys.stdout
timesloopeded = 0

while True:
    t=0
    i=1
    IPsToScan = []
    #Find Local Address
    IPaddr = GetLocalAddress(dik)
    #Find On Network
    TerminalSpam(dik,f'Checking Online Devices')
    IPlist = subprocess.check_output("sudo nmap -sn -T3 "+ IPaddr +" -oG - | awk \'/Up$/{print $2}\'", shell=True).decode("utf-8")
    TerminalSpam(dik,f'Creating IP Checklist')
    for line in IPlist.splitlines():
        if IsValidIpToUse(line):
            IPsToScan.append(line)
            CurrentIPs[line] = datetime.datetime.now()
    for line in IPsToScan:
        time.sleep(1)
        try:
            dik[line] = "Resolving..."
            TerminalSpam(dik,f'Resolving {line}')
            digdata = subprocess.check_output('avahi-resolve-address '+line+' | awk \'{print $2}\'',shell=True).decode("utf-8")
            dik[line] = digdata
            TerminalSpam(dik,f'Resolved {line}')
        except:
            digdata = ""
            dik[line] = digdata
            TerminalSpam(dik,f'Resolved {line}')
    TerminalSpam(dik,f'Triggering Sleep')
    time.sleep(60)
