import os

error_logs = []

for file_name in os.listdir(log_directory):
    print file_name
    app_name = file_name.replace(".log", ".apk")
    app_package = app_name.replace(".apk", "")

    app_log = app_name.replace(".apk", ".log")
    app_log_path = os.path.join(log_directory, app_log)
    app_log_file = open(app_log_path, "r")
    app_log_lines = app_log_file.readlines()

    ## Step-1: find PID
    pid = 0
    for line in app_log_lines:
        line = line.strip()
        if line.startswith("[DexFile]") and app_package in line:
            pid = line.split(" ")[1].split(",")[1]
            break
    # print pid

    pids = []
    for line in app_log_lines:
        line = line.strip()
        if line.startswith("[") and "," in line:
            other_pid = line.split(",")[1]
            if (not (other_pid in pids)) and (int(other_pid) >= int(pid)):
                pids.append(other_pid)
    # for p in pids:
        # print str(p)

    ## Step-2: filter out the log data that belongs to other PIDs
    app_log_map = {} # timestamp -> line of log data
    for line in app_log_lines:
        line = line.strip()
        if ((str(pid) + "," + str(pid)) in line) and (line.startswith("[")):
            timestamp = line.split(" ")[1].split(",")[0]
            if not app_log_map.has_key(timestamp):
                app_log_map[timestamp] = line
            else:
                raise RuntimeError

    app_log_lines_ordered = []
    timestamp_ordered = sorted(app_log_map.keys())
    start_record = False # <- helper flag
    cur_line_ignore = False # <- helper flag
    for timestamp_idx in range(len(timestamp_ordered)):
        timestamp = timestamp_ordered[timestamp_idx]

        # we ignore the log data until we meet the "[DexFile]" tag
        if ("[DexFile]" in app_log_map[timestamp]) and (app_package in app_log_map[timestamp]):
            start_record = True
        if start_record == False:
            continue

        # we ignore the case: [JNI-start] -> [JNI-end]
        if cur_line_ignore:
            cur_line_ignore = False # reset the flag
            continue
            
        cur_line = app_log_map[timestamp]
        nxt_line = ""
        if (timestamp_idx + 1) < len(timestamp_ordered):
            nxt_line = app_log_map[timestamp_ordered[timestamp_idx + 1]]
        if cur_line.startswith("[JNI-start]") and nxt_line.startswith("[JNI-end]"):
            cur_line_ignore = True
            continue
        
        # normal case
        app_log_lines_ordered.append(cur_line)
            
    # for line in app_log_lines_ordered:
        # print line

    # continue to filter out the case "[JNI-start] -> [JNI-end]"
    while True:
        is_stable = True
        app_log_lines_ordered_new = []
        cur_line_ignore = False # <- helper flag
        for line_idx in range(len(app_log_lines_ordered)):
            # we ignore the case: [JNI-start] -> [JNI-end]
            if cur_line_ignore:
                cur_line_ignore = False # reset the flag
                continue
            
            cur_line = app_log_lines_ordered[line_idx]
            nxt_line = ""
            if (line_idx + 1) < len(app_log_lines_ordered):
                nxt_line = app_log_lines_ordered[line_idx + 1]
            if cur_line.startswith("[JNI-start]") and nxt_line.startswith("[JNI-end]"):
                is_stable = False
                cur_line_ignore = True
                continue
                
            # normal case
            app_log_lines_ordered_new.append(cur_line)
        
        if is_stable:
            break
        else:
            app_log_lines_ordered = []
            for line in app_log_lines_ordered_new:
                app_log_lines_ordered.append(line)
            
    # for line in app_log_lines_ordered:
        # print line

    ## Step-3: filter out the log data that is not related to the app's native code
    available_line_range = []
    pre_JNI = False
    pre_DL = False
    nested_cnt = 0
    for line_idx in range(len(app_log_lines_ordered)):
        line = app_log_lines_ordered[line_idx]
        
        if line.startswith("[JNI-") and "com.qihoo." in line:
            continue
        if line.startswith("[JNI-") and "com.tencent." in line:
            continue
        if line.startswith("[JNI-") and "com.baidu." in line:
            continue
        if line.startswith("[JNI-") and "com.mato." in line:
            continue
        if line.startswith("[JNI-") and "com.hhkx." in line:
            continue
        if line.startswith("[JNI-") and "pl." in line:
            continue
        if line.startswith("[JNI-") and "cn.jiguang" in line:
            continue
        if line.startswith("[JNI-") and "cn.jpush" in line:
            continue
        if line.startswith("[JNI-") and "cn.bmob" in line:
            continue
        if line.startswith("[JNI-") and "org.android.spdy" in line:
            continue
        if line.startswith("[JNI-") and "io.objectbox" in line:
            continue
        if line.startswith("[JNI-") and "net.sqlcipher" in line:
            continue
        if line.startswith("[JNI-") and ".onCreate(android.os.Bundle)" in line:
            continue
            
        if line.startswith("[JNI-") and "com.jg." in line:
            continue
            
        if line.startswith("[JNI-") and "o.boe.e" in line:
            continue
        
        if line.startswith("[dlopen-start]") and pre_JNI == False:
            pre_DL = True
            available_line_range.append(line_idx)
        if line.startswith("[dlopen-end]") and pre_JNI == False:
            pre_DL = False
            available_line_range.append(line_idx)
        if line.startswith("[JNI-start]") and pre_DL == False:
            if pre_JNI == True:
                nested_cnt += 1
            pre_JNI = True
            if nested_cnt == 0:
                available_line_range.append(line_idx)
        if line.startswith("[JNI-end]") and pre_DL == False:
            if nested_cnt == 0:
                pre_JNI = False
                available_line_range.append(line_idx)
            else:
                nested_cnt -= 1

    # check
    if not (len(available_line_range) == 1) and not (len(available_line_range) % 2 == 0):
        print "error"
        error_logs.append(app_log_path)
        continue
    
    if len(available_line_range) == 1:
        app_log_lines_ordered_tmp = []
        line_idx_start = available_line_range[0]
        line_idx_end = len(app_log_lines_ordered) - 1
        for line_idx in range(line_idx_start, line_idx_end + 1):
            line = app_log_lines_ordered[line_idx]
            app_log_lines_ordered_tmp.append(line)
            
        app_log_lines_ordered = []
        for line in app_log_lines_ordered_tmp:
            app_log_lines_ordered.append(line)
    
    if len(available_line_range) % 2 == 0:
        for pair_idx in range(len(available_line_range) / 2):
            line_idx_1 = available_line_range[2 * pair_idx]
            line_idx_2 = available_line_range[2 * pair_idx + 1]
            line_1 = app_log_lines_ordered[line_idx_1]
            line_2 = app_log_lines_ordered[line_idx_2]
            # print line_1
            # print line_2
            
            if (line_1.startswith("[dlopen-start]")):
                assert line_2.startswith("[dlopen-end]")
            if (line_1.startswith("[JNI-start]")):
                assert line_2.startswith("[JNI-end]")
                method_1 = line_1.replace(line_1.split(",")[0], "")
                method_2 = line_2.replace(line_2.split(",")[0], "")
                assert method_1 == method_2
            
        # do the real filter
        app_log_lines_ordered_tmp = []
        for pair_idx in range(len(available_line_range) / 2):
            line_idx_start = available_line_range[2 * pair_idx]
            line_idx_end = available_line_range[2 * pair_idx + 1]
            for line_idx in range(line_idx_start, line_idx_end + 1):
                line = app_log_lines_ordered[line_idx]
                app_log_lines_ordered_tmp.append(line)

        app_log_lines_ordered = []
        for line in app_log_lines_ordered_tmp:
            app_log_lines_ordered.append(line)

    #'''
    # add log from the forked process
    if len(app_log_lines_ordered) > 0:
        for p in pids:
            if p == pid:
                continue
            for line in app_log_lines:
                line = line.strip()
                if ((str(p) + "," + str(p)) in line) and (line.startswith("[")):
                    app_log_lines_ordered.append(line)
    #'''

    # '''
    tgt_log_path = os.path.join(tgt_directory, file_name)
    tgt_log_file = open(tgt_log_path, "w")
    for line in app_log_lines_ordered:
        # print line
        tgt_log_file.write(line + "\n")
    tgt_log_file.flush()
    tgt_log_file.close()
    # '''
    
    app_log_file.close()

for log in error_logs:
    print log
    # os.remove(log)
