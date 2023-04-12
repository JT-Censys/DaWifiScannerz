

#Imports
import subprocess, sys, datetime, time, os, random

def Clear(Type):
    match Type:
        case 1:
            con.write("\r                                                                                ")
        case 2:
            os.system("clear")
        case _:
            os.system("clear")

def TwoHoursPassed(value):
    if value < (value + datetime.timedelta(hours=2)): return False
    return True

def GetLocalAddress():
    Clear(1)
    con.write("\rGathering IP and Netmask")
    IPinet = subprocess.check_output("ip -o -f inet addr show wlp2s0 | awk \'/scope global/ {print $4}\'", shell=True).decode("utf-8").replace('\n','')
    Clear(1)
    con.write(f"\rAcquired: {IPinet}")
    return IPinet

def IsValidIpToUse(ip):
    if ip in CurrentIPs.keys():
        if TwoHoursPassed(CurrentIPs[ip]):
            return True
        else:
            return False
    else:
        return True


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
    #Find Local Address
    IPaddr = GetLocalAddress()
    #Find On Network
    IPlist = subprocess.check_output("sudo nmap -sn -T3 "+ IPaddr +" -oG - | awk \'/Up$/{print $2}\'", shell=True).decode("utf-8")
    #Reset Counters
    t = 0
    i = 1
    IPsToScan = []
    dik.clear()
    closed = []
    #Check If Valid IP
    for line in IPlist.splitlines():
        if IsValidIpToUse(line):
            IPsToScan.append(line)
            t += 1
            CurrentIPs[line] = datetime.datetime.now()
    #Scan Valid IP
    RandoIplist = IPsToScan
    for line in IPsToScan:
        PSip = random.choice(RandoIplist)
        RandoIplist.remove(PSip)
        Clear(1)
        con.write(f"\rDevice: {t}|{i}: Port Scanning: {PSip}")
        try:
            o = subprocess.check_output("nmap -n -T4 "+ PSip +" -oG - | awk \'/open/{ s = \"\"; for (i = 5; i <= NF-4; i++) s = s substr($i,1,length($i)-4) \"\\n\"; print $2 \" \" $3 \"\\n\" s}\'", shell=True).decode("utf-8")
            if o != "":
                try:
                    Clear(1)
                    con.write(f"\rDevice: {t}|{i}: Digging: {PSip}")
                    digdata = subprocess.check_output('avahi-resolve-address '+PSip+' | awk \'{print $2}\'',shell=True).decode("utf-8")
                    Clear(2)
                    con.write(f"\rDevice: {t}|{i}: Digging: {PSip}")
                    o = f"mDNS: {digdata}{o}"
                except:
                    o = f"mDNS: FAILED\n{o}"
            dik[PSip] = o    
        except:
            dik[PSip] = ''
        i += 1
    #Save To File
    now = datetime.datetime.now().strftime('%Y.%m.%d-%H.%M.%S')
    with open(f"{now}.txt","w") as datafile:
        for key, value in sorted(dik.items()):
            if value != "":
                datafile.write(f"{key}:\n{value}")
            else:
                closed.append(key)
        datafile.write(f"\nClosed{len(closed)}:{closed}")
        datafile.close()
    #Tell User Done Then Wait For Next Iteration
    timesloopeded += 1
    Clear(1)
    con.write(f"\rDone With Loop: ({timesloopeded}) Devices Scanned({t})")
    time.sleep(1800)