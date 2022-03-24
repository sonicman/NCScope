import os
import shutil

RTD1_apps = []
RTD2_apps = []
RTD3_apps = []
RTD4_apps = []
RTD5_apps = []
RTD6_apps = []
RTD7_apps = []
TPD1_apps = []
TPD2_apps = []
TPD3_apps = []

DBD1_apps = []
DBD2_apps = []
DBD3_apps = []
EMD1_apps = []
EMD2_apps = []
EMD3_apps = []
EMD4_apps = []
DFD1_apps = []
DFD2_apps = []
GDD1_apps = []
GDD2_apps = []
GDD3_apps = []
DCR1_apps = []
DCR2_apps = []
DCR3_apps = []
TCK1_apps = []

for log_name in os.listdir(tgt_directory):
    print log_name

    log_path = os.path.join(tgt_directory, log_name)
    log_file = open(log_path, "r")
    
    package_name = log_name.replace(".log", "")
    
    has_RTD1 = False
    has_RTD2 = False
    has_RTD3 = False
    has_RTD4 = False
    has_RTD5 = False
    has_RTD6 = False
    has_RTD7 = False
    has_TPD1 = False
    has_TPD2 = False
    has_TPD3 = False
    
    has_DBD1 = False
    has_DBD2 = False
    has_DBD3 = False
    has_EMD1 = False
    has_EMD2 = False
    has_EMD3 = False
    has_EMD4 = False
    has_DFD1 = False
    has_DFD2 = False
    has_GDD1 = False
    has_GDD2 = False
    has_GDD3 = False
    has_DCR1 = False
    has_DCR2 = False
    has_DCR3 = False
    has_TCK1 = False
    
    pid = 0
    time_cnt = 0
    gettime_cnt = 0
    for line in log_file:
        line = line.strip()
        if pid == 0:
            pid = line.split(",")[1]
        
        # RTD-1
        if (has_RTD1 == False) and (line.startswith("[access") or line.startswith("[open") or line.startswith("[stat")) and ("bin/su" in line):
            print line
            has_RTD1 = True
            RTD1_apps.append(package_name)
            time_cnt = 0
            gettime_cnt = 0
        # RTD-1
        if (has_RTD1 == False) and (line.startswith("[access") or line.startswith("[open") or line.startswith("[stat")) and ("Superuser" in line or "chainfire" in line or "noshufou" in line or "magisk" in line):
            print line
            has_RTD1 = True
            RTD1_apps.append(package_name)
            time_cnt = 0
            gettime_cnt = 0
        # RTD-2
        if (has_RTD2 == False) and (line.startswith("[exec")) and ("which" in line or "su" in line or "busybox" in line):
            print line
            has_RTD2 = True
            RTD2_apps.append(package_name)
            time_cnt = 0
            gettime_cnt = 0
        # RTD-3
        if (has_RTD3 == False) and (line.startswith("[strcmp") or line.startswith("[strcasecmp") or line.startswith("[strncmp") or line.startswith("[strncasecmp") or line.startswith("[strstr")) and ("Superuser" in line or "chainfire" in line or "noshufou" in line or "magisk" in line):
            print line
            has_RTD3 = True
            RTD3_apps.append(package_name)
            time_cnt = 0
            gettime_cnt = 0
        # RTD-4
        if (has_RTD4 == False) and (line.startswith("[exec")) and ("mount" in line):
            print line
            has_RTD4 = True
            RTD4_apps.append(package_name)
            time_cnt = 0
            gettime_cnt = 0
        # RTD-5
        if (has_RTD5 == False) and (line.startswith("[strcmp") or line.startswith("[strcasecmp") or line.startswith("[strncmp") or line.startswith("[strncasecmp") or line.startswith("[strstr")) and ("test-keys" in line):
            print line
            has_RTD5 = True
            RTD5_apps.append(package_name)
            time_cnt = 0
            gettime_cnt = 0
        # RTD-6
        if (has_RTD6 == False) and (line.startswith("[__system")) and ("ro.debuggable" in line or "ro.secure" in line) and line.split(",")[1] == pid:
            print line
            has_RTD6 = True
            RTD6_apps.append(package_name)
            time_cnt = 0
            gettime_cnt = 0
        # RTD-7
        if (has_RTD7 == False) and (line.startswith("[exec")) and ("ps" in line):
            print line
            has_RTD7 = True
            RTD7_apps.append(package_name)
            time_cnt = 0
            gettime_cnt = 0
       
        # DBD-1
        if (has_DBD1 == False) and (line.startswith("[isDebugger")):
            print line
            has_DBD1 = True
            DBD1_apps.append(package_name)
            time_cnt = 0
            gettime_cnt = 0
        # DBD-2
        if (has_DBD2 == False) and (line.startswith("[strcmp") or line.startswith("[strcasecmp") or line.startswith("[strncmp") or line.startswith("[strncasecmp") or line.startswith("[strstr")) and ("TracerPid" in line):
            print line
            has_DBD2 = True
            DBD2_apps.append(package_name)
            time_cnt = 0
            gettime_cnt = 0
        # DBD-3
        if (has_DBD3 == False) and (line.startswith("[__system")) and ("debug.atrace" in line) and line.split(",")[1] == pid:
            print line
            has_DBD3 = True
            DBD3_apps.append(package_name)
            time_cnt = 0
            gettime_cnt = 0
        # EMD1
        if (has_EMD1 == False) and (line.startswith("[open")) and ("/proc/tty/driver" in line):
            print line
            has_EMD1 = True
            EMD1_apps.append(package_name)
            time_cnt = 0
            gettime_cnt = 0
        # EMD2
        if (has_EMD2 == False) and (line.startswith("[__system")) and ("qemu" in line):
            print line
            has_EMD2 = True
            EMD2_apps.append(package_name)
            time_cnt = 0
            gettime_cnt = 0
        # EMD3
        if (has_EMD3 == False) and ("goldfish" in line or "unknown" in line):
            print line
            has_EMD3 = True
            EMD3_apps.append(package_name)
            time_cnt = 0
            gettime_cnt = 0
        # EMD4
        if (has_EMD4 == False) and ("TelephonyManager" in line):
            print line
            has_EMD4 = True
            EMD4_apps.append(package_name)
            time_cnt = 0
            gettime_cnt = 0
        # DFD1
        if (has_DFD1 == False) and ("xposed" in line or "frida" in line or "reverse" in line):
            print line
            has_DFD1 = True
            DFD1_apps.append(package_name)
            time_cnt = 0
            gettime_cnt = 0
        # DFD2
        # if (has_DFD2 == False) and (line.startswith("[exec")) and ("ss" in line or "netstat" in line):
        if (has_DFD2 == False) and (line.startswith("[strcmp") or line.startswith("[strcasecmp") or line.startswith("[strncmp") or line.startswith("[strncasecmp") or line.startswith("[strstr")) and ("27042" in line):
            has_DFD2 = True
            # DFD2_apps.append(package_name)
            time_cnt = 0
            gettime_cnt = 0
        
        # GDD1
        if (has_GDD1 == False) and (line.startswith("[time")):
            if line.split(",")[1] == pid:
                if time_cnt >= 6:
                    has_GDD1 = True
                    GDD1_apps.append(package_name)
                    time_cnt = 0
                else:
                    time_cnt += 1
            else:
                time_cnt = 0
            gettime_cnt = 0
        # GDD2
        if (has_GDD2 == False) and (line.startswith("[gettime")):
            if line.split(",")[1] == pid:
                if gettime_cnt >= 6:
                    has_GDD2 = True
                    GDD2_apps.append(package_name)
                    gettime_cnt = 0
                else:
                    gettime_cnt += 1
            else:
                gettime_cnt = 0
            time_cnt = 0
        # GDD3
        if (has_GDD3 == False) and ("fake-libs" not in line) and ("liblog.so" in line.split(",")[-1] or "liblog.so" in line.split(",")[-2] or "libart.so" in line.split(",")[-1] or "libart.so" in line.split(",")[-2] or "libc.so" in line.split(",")[-1] or "libc.so" in line.split(",")[-2]):
            print line
            has_GDD3 = True
            GDD3_apps.append(package_name)
            time_cnt = 0
            gettime_cnt = 0
        
        # DCR1
        if (has_DCR1 == False) and (line.startswith("[DexFile") and (package_name + "-") not in line and "/system" not in line):
            print line
            has_DCR1 = True
            DCR1_apps.append(package_name)
            time_cnt = 0
            gettime_cnt = 0
        # DCR3
        if (has_DCR3 == False) and (line.startswith("[mmap-start") and int(line.split(",")[-1]) & 0x4 == 0x4) and line.split(",")[1] == pid:
            print line
            has_DCR3 = True
            DCR3_apps.append(package_name)
            time_cnt = 0
            gettime_cnt = 0
            
        if (has_TCK1 == False) and ("libjiagu.so" in line or "libjiagu_64.so" in line or "libexec.so" in line):
            print line
            has_TCK1 = True
            TCK1_apps.append(package_name)
            time_cnt = 0
            gettime_cnt = 0
        
                
    log_file.close()

print "RTD1: " + str(len(RTD1_apps))
print "RTD2: " + str(len(RTD2_apps))
print "RTD3: " + str(len(RTD3_apps)) 
print "RTD4: " + str(len(RTD4_apps)) 
print "RTD5: " + str(len(RTD5_apps)) 
print "RTD6: " + str(len(RTD6_apps)) 
print "RTD7: " + str(len(RTD7_apps)) 
RTD_set = set(RTD1_apps).union(set(RTD2_apps), set(RTD3_apps), set(RTD4_apps), set(RTD5_apps), set(RTD6_apps), set(RTD7_apps))
print len(RTD_set)
#print len(set(RTD1_apps) & set(RTD2_apps))

for package in RTD_set:
    print "[RTD]: " + package

print "DBD1: " + str(len(DBD1_apps))
print "DBD2: " + str(len(DBD2_apps))
print "DBD3: " + str(len(DBD3_apps))
DBD_set = set(DBD1_apps).union(set(DBD2_apps), set(DBD3_apps))
print len(DBD_set)
#print len(set(DBD1_apps) & set(DBD2_apps))

for package in DBD_set:
    print "[DBD]: " + package

print "EMD1: " + str(len(EMD1_apps))
print "EMD2: " + str(len(EMD2_apps))
print "EMD3: " + str(len(EMD3_apps))
print "EMD4: " + str(len(EMD4_apps))
EMD_set = set(EMD1_apps).union(set(EMD2_apps), set(EMD3_apps), set(EMD4_apps))
print len(EMD_set)

for package in EMD_set:
    print "[EMD]: " + package

EMD_set12 = set(set(EMD1_apps) & set(EMD2_apps))
EMD_set13 = set(set(EMD1_apps) & set(EMD3_apps))
EMD_set23 = set(set(EMD2_apps) & set(EMD3_apps))
EMD_set2 = EMD_set12.union(EMD_set13, EMD_set23)
print len(EMD_set2)

print "DFD1: " + str(len(DFD1_apps))
print "DFD2: " + str(len(DFD2_apps))
DFD_set = set(DFD1_apps).union(DFD2_apps)
print len(DFD_set)

for package in DFD_set:
    print "[DFD]: " + package

print "GDD1: " + str(len(GDD1_apps))
print "GDD2: " + str(len(GDD2_apps))
print "GDD3: " + str(len(GDD3_apps))
GDD_set = set(GDD1_apps).union(set(GDD2_apps), set(GDD3_apps))
print len(GDD_set)

# print len(set(GDD1_apps) & set(GDD2_apps) & set(GDD3_apps))

GDD_set12 = set(set(GDD1_apps) & set(GDD2_apps))
GDD_set13 = set(set(GDD1_apps) & set(GDD3_apps))
GDD_set23 = set(set(GDD2_apps) & set(GDD3_apps))
GDD_set2 = GDD_set12.union(GDD_set13, GDD_set23)
print len(GDD_set2)

DCR1_apps = list(set(DCR1_apps).difference(set(GDD3_apps)))
print "DCR1: " + str(len(DCR1_apps))
DCR2_apps = list(set(DCR2_apps).union(set(GDD3_apps)))
print "DCR2: " + str(len(DCR2_apps))
DCR12_apps = set(DCR1_apps).union(set(DCR2_apps))
print "DCR12: " + str(len(DCR12_apps))
print "DCR3: " + str(len(DCR3_apps))
DCR_set = set(DCR1_apps).union(set(DCR2_apps), set(DCR3_apps), set(GDD3_apps))
print len(DCR_set)

DCR_set13 = set(set(DCR1_apps) & set(DCR3_apps))
DCR_set23 = set(set(DCR2_apps) & set(DCR3_apps))
DCR_set2 = set(DCR_set13).union(set(DCR_set23))
print len(DCR_set2)

TCK_set = set(TCK1_apps)
print "TCK1: " + str(len(TCK_set))

AA_set = DBD_set.union(EMD_set, DFD_set, DCR_set, TCK_set)
print "AA: " + str(len(AA_set))

TOTAL_set = RTD_set.union(DBD_set, EMD_set, DFD_set, GDD_set, DCR_set)
print "TOTAL: " + str(len(TOTAL_set))

for package in DBD_set.difference(TCK_set):
    print "[****]: " + package


app_map = {}
for package in RTD1_apps:
    if app_map.has_key(package):
        app_map[package] += 1
    else:
        app_map[package] = 0
for package in RTD2_apps:
    if app_map.has_key(package):
        app_map[package] += 1
    else:
        app_map[package] = 0
for package in RTD3_apps:
    if app_map.has_key(package):
        app_map[package] += 1
    else:
        app_map[package] = 1
for package in DBD1_apps:
    if app_map.has_key(package):
        app_map[package] += 1
    else:
        app_map[package] = 0
for package in DBD2_apps:
    if app_map.has_key(package):
        app_map[package] += 1
    else:
        app_map[package] = 0
for package in DBD3_apps:
    if app_map.has_key(package):
        app_map[package] += 1
    else:
        app_map[package] = 0
for package in EMD1_apps:
    if app_map.has_key(package):
        app_map[package] += 1
    else:
        app_map[package] = 0
for package in EMD2_apps:
    if app_map.has_key(package):
        app_map[package] += 1
    else:
        app_map[package] = 0
for package in EMD3_apps:
    if app_map.has_key(package):
        app_map[package] += 1
    else:
        app_map[package] = 0
for package in DFD1_apps:
    if app_map.has_key(package):
        app_map[package] += 1
    else:
        app_map[package] = 0
for package in GDD1_apps:
    if app_map.has_key(package):
        app_map[package] += 1
    else:
        app_map[package] = 0
for package in GDD2_apps:
    if app_map.has_key(package):
        app_map[package] += 1
    else:
        app_map[package] = 0
for package in GDD3_apps:
    if app_map.has_key(package):
        app_map[package] += 1
    else:
        app_map[package] = 0
for package in DCR1_apps:
    if app_map.has_key(package):
        app_map[package] += 1
    else:
        app_map[package] = 0
for package in DCR2_apps:
    if app_map.has_key(package):
        app_map[package] += 1
    else:
        app_map[package] = 0
for package in DCR3_apps:
    if app_map.has_key(package):
        app_map[package] += 1
    else:
        app_map[package] = 0

for package in app_map.keys():
    # print "%s %d" % (package, app_map[package])
    if app_map[package] > 1:
        print package

