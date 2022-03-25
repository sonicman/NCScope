#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from time import sleep
import sys
from socket import inet_ntop, ntohs, AF_INET, AF_INET6
from struct import pack, unpack

# load BPF program
b = BPF(text="""

#include <linux/sched.h>
#include <uapi/linux/ptrace.h>
#include <net/sock.h>

// strcmp //

struct strcmp_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p0[64];
    char p1[64];
};
BPF_HASH(strcmp_records, u64, struct strcmp_param);

int strcmp_hook(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx) || !PT_REGS_PARM2(ctx))
        return 0;
        
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();
    
    struct strcmp_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p0, sizeof(record.p0), (void *)PT_REGS_PARM1(ctx));
    bpf_probe_read(&record.p1, sizeof(record.p1), (void *)PT_REGS_PARM2(ctx));
    
    if (record.p0[0] == 'L' || record.p1[0] == 'L') // filter
        return 0;
    if (record.p0[0] == '[' || record.p1[0] == '[') // filter
        return 0;
    if (record.p0[0] == '_' || record.p1[0] == '_') // filter
        return 0;
    if (record.p0[0] == '<' || record.p1[0] == '<') // filter
        return 0;
    if (record.p0[0] == '\\0' || record.p1[0] == '\\0') // filter
        return 0;
    // if (record.p0[1] == '\\0' || record.p1[1] == '\\0') // filter
    //     return 0;
    // if (record.p0[2] == '\\0' || record.p1[2] == '\\0') // filter
    //     return 0;
    
    if ((record.p0[0]=='g' && record.p0[1]=='l')
     || (record.p1[0]=='g' && record.p1[1]=='l')) // filter
        return 0;
    if ((record.p0[0]=='p' && record.p0[1]=='i' && record.p0[2]=='c')
     || (record.p1[0]=='p' && record.p1[1]=='i' && record.p1[2]=='c')) // filter
        return 0;
    if ((record.p0[0]=='.' && record.p0[1]=='a' && record.p0[2]=='r' && record.p0[3]=='t')
     || (record.p1[0]=='.' && record.p1[1]=='a' && record.p1[2]=='r' && record.p1[3]=='t')) // filter
        return 0;
    if ((record.p0[4]=='.' && record.p0[5]=='a' && record.p0[6]=='r' && record.p0[7]=='t')
     || (record.p1[4]=='.' && record.p1[5]=='a' && record.p1[6]=='r' && record.p1[7]=='t')) // filter
        return 0;
    if ((record.p0[0]=='i' && record.p0[1]=='n' && record.p0[2]=='i' && record.p0[3]=='t')
     || (record.p1[0]=='i' && record.p1[1]=='n' && record.p1[2]=='i' && record.p1[3]=='t')) // filter
        return 0;
    if ((record.p0[0]=='c' && record.p0[1]=='l' && record.p0[2]=='i' && record.p0[3]=='n') 
     || (record.p1[0]=='c' && record.p1[1]=='l' && record.p1[2]=='i' && record.p1[3]=='n')) // filter
        return 0;
    if ((record.p0[0]=='f' && record.p0[1]=='i' && record.p0[2]=='n' && record.p0[3]=='a') 
     || (record.p1[0]=='f' && record.p1[1]=='i' && record.p1[2]=='n' && record.p1[3]=='a')) // filter
        return 0;
    
    strcmp_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// strcasecmp //

struct strcasecmp_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p0[64];
    char p1[64];
};
BPF_HASH(strcasecmp_records, u64, struct strcasecmp_param);

int strcasecmp_hook(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx) || !PT_REGS_PARM2(ctx))
        return 0;
        
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();
    
    struct strcasecmp_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p0, sizeof(record.p0), (void *)PT_REGS_PARM1(ctx));
    bpf_probe_read(&record.p1, sizeof(record.p1), (void *)PT_REGS_PARM2(ctx));
    
    if (record.p0[0] == 'L' || record.p1[0] == 'L') // filter
        return 0;
    if (record.p0[0] == '[' || record.p1[0] == '[') // filter
        return 0;
    if (record.p0[0] == '_' || record.p1[0] == '_') // filter
        return 0;
    if (record.p0[0] == '<' || record.p1[0] == '<') // filter
        return 0;
    if (record.p0[0] == '\\0' || record.p1[0] == '\\0') // filter
        return 0;
    // if (record.p0[1] == '\\0' || record.p1[1] == '\\0') // filter
    //     return 0;
    // if (record.p0[2] == '\\0' || record.p1[2] == '\\0') // filter
    //     return 0;
    
    if ((record.p0[0]=='g' && record.p0[1]=='l')
     || (record.p1[0]=='g' && record.p1[1]=='l')) // filter
        return 0;
    if ((record.p0[0]=='p' && record.p0[1]=='i' && record.p0[2]=='c')
     || (record.p1[0]=='p' && record.p1[1]=='i' && record.p1[2]=='c')) // filter
        return 0;
    if ((record.p0[0]=='.' && record.p0[1]=='a' && record.p0[2]=='r' && record.p0[3]=='t')
     || (record.p1[0]=='.' && record.p1[1]=='a' && record.p1[2]=='r' && record.p1[3]=='t')) // filter
        return 0;
    if ((record.p0[4]=='.' && record.p0[5]=='a' && record.p0[6]=='r' && record.p0[7]=='t')
     || (record.p1[4]=='.' && record.p1[5]=='a' && record.p1[6]=='r' && record.p1[7]=='t')) // filter
        return 0;
    if ((record.p0[0]=='i' && record.p0[1]=='n' && record.p0[2]=='i' && record.p0[3]=='t')
     || (record.p1[0]=='i' && record.p1[1]=='n' && record.p1[2]=='i' && record.p1[3]=='t')) // filter
        return 0;
    if ((record.p0[0]=='c' && record.p0[1]=='l' && record.p0[2]=='i' && record.p0[3]=='n') 
     || (record.p1[0]=='c' && record.p1[1]=='l' && record.p1[2]=='i' && record.p1[3]=='n')) // filter
        return 0;
    if ((record.p0[0]=='f' && record.p0[1]=='i' && record.p0[2]=='n' && record.p0[3]=='a') 
     || (record.p1[0]=='f' && record.p1[1]=='i' && record.p1[2]=='n' && record.p1[3]=='a')) // filter
        return 0;
    
    strcasecmp_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// strncmp //

struct strncmp_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p0[64];
    char p1[64];
};
BPF_HASH(strncmp_records, u64, struct strncmp_param);

int strncmp_hook(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx) || !PT_REGS_PARM2(ctx))
        return 0;
        
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct strncmp_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p0, sizeof(record.p0), (void *)PT_REGS_PARM1(ctx));
    bpf_probe_read(&record.p1, sizeof(record.p1), (void *)PT_REGS_PARM2(ctx));
    
    if (record.p0[0] == 'L' || record.p1[0] == 'L') // filter
        return 0;
    if (record.p0[0] == '[' || record.p1[0] == '[') // filter
        return 0;
    if (record.p0[0] == '_' || record.p1[0] == '_') // filter
        return 0;
    if (record.p0[0] == '<' || record.p1[0] == '<') // filter
        return 0;
    if (record.p0[0] == '\\0' || record.p1[0] == '\\0') // filter
        return 0;
    // if (record.p0[1] == '\\0' || record.p1[1] == '\\0') // filter
    //     return 0;
    // if (record.p0[2] == '\\0' || record.p1[2] == '\\0') // filter
    //     return 0;
    
    if ((record.p0[0]=='g' && record.p0[1]=='l')
     || (record.p1[0]=='g' && record.p1[1]=='l')) // filter
        return 0;
    if ((record.p0[0]=='p' && record.p0[1]=='i' && record.p0[2]=='c')
     || (record.p1[0]=='p' && record.p1[1]=='i' && record.p1[2]=='c')) // filter
        return 0;
    if ((record.p0[0]=='.' && record.p0[1]=='a' && record.p0[2]=='r' && record.p0[3]=='t')
     || (record.p1[0]=='.' && record.p1[1]=='a' && record.p1[2]=='r' && record.p1[3]=='t')) // filter
        return 0;
    if ((record.p0[4]=='.' && record.p0[5]=='a' && record.p0[6]=='r' && record.p0[7]=='t')
     || (record.p1[4]=='.' && record.p1[5]=='a' && record.p1[6]=='r' && record.p1[7]=='t')) // filter
        return 0;
    if ((record.p0[0]=='i' && record.p0[1]=='n' && record.p0[2]=='i' && record.p0[3]=='t')
     || (record.p1[0]=='i' && record.p1[1]=='n' && record.p1[2]=='i' && record.p1[3]=='t')) // filter
        return 0;
    if ((record.p0[0]=='c' && record.p0[1]=='l' && record.p0[2]=='i' && record.p0[3]=='n') 
     || (record.p1[0]=='c' && record.p1[1]=='l' && record.p1[2]=='i' && record.p1[3]=='n')) // filter
        return 0;
    if ((record.p0[0]=='f' && record.p0[1]=='i' && record.p0[2]=='n' && record.p0[3]=='a') 
     || (record.p1[0]=='f' && record.p1[1]=='i' && record.p1[2]=='n' && record.p1[3]=='a')) // filter
        return 0;
    
    strncmp_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// strncasecmp //

struct strncasecmp_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p0[64];
    char p1[64];
};
BPF_HASH(strncasecmp_records, u64, struct strncasecmp_param);

int strncasecmp_hook(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx) || !PT_REGS_PARM2(ctx))
        return 0;
        
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct strncasecmp_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p0, sizeof(record.p0), (void *)PT_REGS_PARM1(ctx));
    bpf_probe_read(&record.p1, sizeof(record.p1), (void *)PT_REGS_PARM2(ctx));
    
    if (record.p0[0] == 'L' || record.p1[0] == 'L') // filter
        return 0;
    if (record.p0[0] == '[' || record.p1[0] == '[') // filter
        return 0;
    if (record.p0[0] == '_' || record.p1[0] == '_') // filter
        return 0;
    if (record.p0[0] == '<' || record.p1[0] == '<') // filter
        return 0;
    if (record.p0[0] == '\\0' || record.p1[0] == '\\0') // filter
        return 0;
    // if (record.p0[1] == '\\0' || record.p1[1] == '\\0') // filter
    //     return 0;
    // if (record.p0[2] == '\\0' || record.p1[2] == '\\0') // filter
    //     return 0;
    
    if ((record.p0[0]=='g' && record.p0[1]=='l')
     || (record.p1[0]=='g' && record.p1[1]=='l')) // filter
        return 0;
    if ((record.p0[0]=='p' && record.p0[1]=='i' && record.p0[2]=='c')
     || (record.p1[0]=='p' && record.p1[1]=='i' && record.p1[2]=='c')) // filter
        return 0;
    if ((record.p0[0]=='.' && record.p0[1]=='a' && record.p0[2]=='r' && record.p0[3]=='t')
     || (record.p1[0]=='.' && record.p1[1]=='a' && record.p1[2]=='r' && record.p1[3]=='t')) // filter
        return 0;
    if ((record.p0[4]=='.' && record.p0[5]=='a' && record.p0[6]=='r' && record.p0[7]=='t')
     || (record.p1[4]=='.' && record.p1[5]=='a' && record.p1[6]=='r' && record.p1[7]=='t')) // filter
        return 0;
    if ((record.p0[0]=='i' && record.p0[1]=='n' && record.p0[2]=='i' && record.p0[3]=='t')
     || (record.p1[0]=='i' && record.p1[1]=='n' && record.p1[2]=='i' && record.p1[3]=='t')) // filter
        return 0;
    if ((record.p0[0]=='c' && record.p0[1]=='l' && record.p0[2]=='i' && record.p0[3]=='n') 
     || (record.p1[0]=='c' && record.p1[1]=='l' && record.p1[2]=='i' && record.p1[3]=='n')) // filter
        return 0;
    if ((record.p0[0]=='f' && record.p0[1]=='i' && record.p0[2]=='n' && record.p0[3]=='a') 
     || (record.p1[0]=='f' && record.p1[1]=='i' && record.p1[2]=='n' && record.p1[3]=='a')) // filter
        return 0;
    
    strncasecmp_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// strstr //

struct strstr_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p0[64];
    char p1[64];
};
BPF_HASH(strstr_records, u64, struct strstr_param);

int strstr_hook(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx) || !PT_REGS_PARM2(ctx))
        return 0;
        
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct strstr_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p0, sizeof(record.p0), (void *)PT_REGS_PARM1(ctx));
    bpf_probe_read(&record.p1, sizeof(record.p1), (void *)PT_REGS_PARM2(ctx));
    
    if (record.p0[0] == 'L' || record.p1[0] == 'L') // filter
        return 0;
    if (record.p0[0] == '[' || record.p1[0] == '[') // filter
        return 0;
    if (record.p0[0] == '_' || record.p1[0] == '_') // filter
        return 0;
    if (record.p0[0] == '<' || record.p1[0] == '<') // filter
        return 0;
    if (record.p0[0] == '\\0' || record.p1[0] == '\\0') // filter
        return 0;
    // if (record.p0[1] == '\\0' || record.p1[1] == '\\0') // filter
    //     return 0;
    // if (record.p0[2] == '\\0' || record.p1[2] == '\\0') // filter
    //     return 0;
    
    if ((record.p0[0]=='g' && record.p0[1]=='l')
     || (record.p1[0]=='g' && record.p1[1]=='l')) // filter
        return 0;
    if ((record.p0[0]=='p' && record.p0[1]=='i' && record.p0[2]=='c')
     || (record.p1[0]=='p' && record.p1[1]=='i' && record.p1[2]=='c')) // filter
        return 0;
    if ((record.p0[0]=='.' && record.p0[1]=='a' && record.p0[2]=='r' && record.p0[3]=='t')
     || (record.p1[0]=='.' && record.p1[1]=='a' && record.p1[2]=='r' && record.p1[3]=='t')) // filter
        return 0;
    if ((record.p0[4]=='.' && record.p0[5]=='a' && record.p0[6]=='r' && record.p0[7]=='t')
     || (record.p1[4]=='.' && record.p1[5]=='a' && record.p1[6]=='r' && record.p1[7]=='t')) // filter
        return 0;
    if ((record.p0[0]=='i' && record.p0[1]=='n' && record.p0[2]=='i' && record.p0[3]=='t')
     || (record.p1[0]=='i' && record.p1[1]=='n' && record.p1[2]=='i' && record.p1[3]=='t')) // filter
        return 0;
    if ((record.p0[0]=='c' && record.p0[1]=='l' && record.p0[2]=='i' && record.p0[3]=='n') 
     || (record.p1[0]=='c' && record.p1[1]=='l' && record.p1[2]=='i' && record.p1[3]=='n')) // filter
        return 0;
    if ((record.p0[0]=='f' && record.p0[1]=='i' && record.p0[2]=='n' && record.p0[3]=='a') 
     || (record.p1[0]=='f' && record.p1[1]=='i' && record.p1[2]=='n' && record.p1[3]=='a')) // filter
        return 0;
    
    strstr_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// open //

struct open_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p0[128];
};
BPF_HASH(open_records, u64, struct open_param);

int open_hook(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;
        
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct open_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p0, sizeof(record.p0), (void *)PT_REGS_PARM1(ctx));
    
    if (record.p0[0] == '\\0') // filter
        return 0;
    
    open_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// openat //

struct openat_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p1[128];
};
BPF_HASH(openat_records, u64, struct openat_param);

int openat_hook(struct pt_regs *ctx) {
    if (!PT_REGS_PARM2(ctx))
        return 0;
        
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct openat_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p1, sizeof(record.p1), (void *)PT_REGS_PARM2(ctx));
    
    if (record.p1[0] == '\\0') // filter
        return 0;
    
    openat_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// fopen //

struct fopen_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p0[128];
};
BPF_HASH(fopen_records, u64, struct fopen_param);

int fopen_hook(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;
        
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct fopen_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p0, sizeof(record.p0), (void *)PT_REGS_PARM1(ctx));
    
    if (record.p0[0] == '\\0') // filter
        return 0;
    
    fopen_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// write //

struct write_param {
    u64 ts;
    u32 pid;
    u32 tid;
    u32 p2;
};
BPF_HASH(write_records, u64, struct write_param);

int write_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct write_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    record.p2 = PT_REGS_PARM3(ctx);
    
    write_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// access //

struct access_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p0[128];
};
BPF_HASH(access_records, u64, struct access_param);

int access_hook(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;
        
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct access_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p0, sizeof(record.p0), (void *)PT_REGS_PARM1(ctx));
    
    if (record.p0[0] == '\\0') // filter
        return 0;
    
    access_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// stat //

struct stat_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p0[128];
};
BPF_HASH(stat_records, u64, struct stat_param);

int stat_hook(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;
        
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct stat_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p0, sizeof(record.p0), (void *)PT_REGS_PARM1(ctx));
    
    if (record.p0[0] == '\\0') // filter
        return 0;
    
    stat_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// __system_property_get //

struct sys_property_get_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p0[128];
};
BPF_HASH(sys_property_get_records, u64, struct sys_property_get_param);

int sys_property_get_hook(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;
        
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct sys_property_get_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p0, sizeof(record.p0), (void *)PT_REGS_PARM1(ctx));
    
    if (record.p0[0] == '\\0') // filter
        return 0;
    
    sys_property_get_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// popen //

struct popen_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p0[128];
};
BPF_HASH(popen_records, u64, struct popen_param);

int popen_hook(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;
        
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct popen_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p0, sizeof(record.p0), (void *)PT_REGS_PARM1(ctx));
    
    if (record.p0[0] == '\\0') // filter
        return 0;
    
    popen_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// execl //

struct execl_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p0[64];
    char p1[64];
    char p2[64];
    char p3[64];
};
BPF_HASH(execl_records, u64, struct execl_param);

int execl_hook(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;
        
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct execl_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p0, sizeof(record.p0), (void *)PT_REGS_PARM1(ctx));
    record.p0[63] = 0;
    bpf_probe_read(&record.p1, sizeof(record.p1), (void *)PT_REGS_PARM2(ctx));
    record.p1[63] = 0;
    bpf_probe_read(&record.p2, sizeof(record.p2), (void *)PT_REGS_PARM3(ctx));
    record.p2[63] = 0;
    bpf_probe_read(&record.p3, sizeof(record.p3), (void *)PT_REGS_PARM4(ctx));
    record.p3[63] = 0;
    
    // if (record.p0[0] == '/')
    //     bpf_probe_read(&record.p1, sizeof(record.p1), (void *)PT_REGS_PARM2(ctx));
    
    execl_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// execle //

struct execle_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p0[64];
    char p1[64];
    char p2[64];
    char p3[64];
};
BPF_HASH(execle_records, u64, struct execle_param);

int execle_hook(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;
        
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct execle_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p0, sizeof(record.p0), (void *)PT_REGS_PARM1(ctx));
    record.p0[63] = 0;
    bpf_probe_read(&record.p1, sizeof(record.p1), (void *)PT_REGS_PARM2(ctx));
    record.p1[63] = 0;
    bpf_probe_read(&record.p2, sizeof(record.p2), (void *)PT_REGS_PARM3(ctx));
    record.p2[63] = 0;
    bpf_probe_read(&record.p3, sizeof(record.p3), (void *)PT_REGS_PARM4(ctx));
    record.p3[63] = 0;
    
    // if (record.p0[0] == '/')
    //     bpf_probe_read(&record.p1, sizeof(record.p1), (void *)PT_REGS_PARM2(ctx));
    
    execle_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// execlp //

struct execlp_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p0[64];
    char p1[64];
    char p2[64];
    char p3[64];
};
BPF_HASH(execlp_records, u64, struct execlp_param);

int execlp_hook(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;
        
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct execlp_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p0, sizeof(record.p0), (void *)PT_REGS_PARM1(ctx));
    record.p0[63] = 0;
    bpf_probe_read(&record.p1, sizeof(record.p1), (void *)PT_REGS_PARM2(ctx));
    record.p1[63] = 0;
    bpf_probe_read(&record.p2, sizeof(record.p2), (void *)PT_REGS_PARM3(ctx));
    record.p2[63] = 0;
    bpf_probe_read(&record.p3, sizeof(record.p3), (void *)PT_REGS_PARM4(ctx));
    record.p3[63] = 0;
    
    // if (record.p0[0] == '/')
    //     bpf_probe_read(&record.p1, sizeof(record.p1), (void *)PT_REGS_PARM2(ctx));
    
    execlp_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// execv //

struct execv_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p0[64];
    char p1[64];
    char p2[64];
    char p3[64];
};
BPF_HASH(execv_records, u64, struct execv_param);

int execv_hook(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;
        
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct execv_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p0, sizeof(record.p0), (void *)PT_REGS_PARM1(ctx));
    record.p0[63] = 0;
    bpf_probe_read(&record.p1, sizeof(record.p1), (void *)PT_REGS_PARM2(ctx));
    record.p1[63] = 0;
    bpf_probe_read(&record.p2, sizeof(record.p2), (void *)PT_REGS_PARM3(ctx));
    record.p2[63] = 0;
    bpf_probe_read(&record.p3, sizeof(record.p3), (void *)PT_REGS_PARM4(ctx));
    record.p3[63] = 0;
    
    // if (record.p0[0] == '/')
    //     bpf_probe_read(&record.p1, sizeof(record.p1), (void *)PT_REGS_PARM2(ctx));
    
    execv_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// execvp //

struct execvp_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p0[64];
    char p1[64];
    char p2[64];
    char p3[64];
};
BPF_HASH(execvp_records, u64, struct execvp_param);

int execvp_hook(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;
        
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct execvp_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p0, sizeof(record.p0), (void *)PT_REGS_PARM1(ctx));
    record.p0[63] = 0;
    bpf_probe_read(&record.p1, sizeof(record.p1), (void *)PT_REGS_PARM2(ctx));
    record.p1[63] = 0;
    bpf_probe_read(&record.p2, sizeof(record.p2), (void *)PT_REGS_PARM3(ctx));
    record.p2[63] = 0;
    bpf_probe_read(&record.p3, sizeof(record.p3), (void *)PT_REGS_PARM4(ctx));
    record.p3[63] = 0;
    
    // if (record.p0[0] == '/')
    //     bpf_probe_read(&record.p1, sizeof(record.p1), (void *)PT_REGS_PARM2(ctx));
    
    execvp_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// execvpe //

struct execvpe_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p0[64];
    char p1[64];
    char p2[64];
    char p3[64];
};
BPF_HASH(execvpe_records, u64, struct execvpe_param);

int execvpe_hook(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;
        
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct execvpe_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p0, sizeof(record.p0), (void *)PT_REGS_PARM1(ctx));
    record.p0[63] = 0;
    bpf_probe_read(&record.p1, sizeof(record.p1), (void *)PT_REGS_PARM2(ctx));
    record.p1[63] = 0;
    bpf_probe_read(&record.p2, sizeof(record.p2), (void *)PT_REGS_PARM3(ctx));
    record.p2[63] = 0;
    bpf_probe_read(&record.p3, sizeof(record.p3), (void *)PT_REGS_PARM4(ctx));
    record.p3[63] = 0;
    
    // if (record.p0[0] == '/')
    //     bpf_probe_read(&record.p1, sizeof(record.p1), (void *)PT_REGS_PARM2(ctx));
    
    execvpe_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// mmap //

struct mmap_enter_param {
    u64 ts;
    u32 pid;
    u32 tid;
    u64 p0;
    u64 p1;
    u32 p2;
};
BPF_HASH(mmap_enter_records, u64, struct mmap_enter_param);

int mmap_enter_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct mmap_enter_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    record.p0 = PT_REGS_PARM1(ctx);
    record.p1 = PT_REGS_PARM2(ctx);
    record.p2 = PT_REGS_PARM3(ctx);
    
    mmap_enter_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

struct mmap_return_param {
    u64 ts;
    u32 pid;
    u32 tid;
    u64 ret;
};
BPF_HASH(mmap_return_records, u64, struct mmap_return_param);

int mmap_return_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct mmap_return_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    record.ret = PT_REGS_RC(ctx);
    
    mmap_return_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// mprotect //

struct mprotect_param {
    u64 ts;
    u32 pid;
    u32 tid;
    u64 p0;
    u64 p1;
    u32 p2;
};
BPF_HASH(mprotect_records, u64, struct mprotect_param);

int mprotect_hook(struct pt_regs *ctx) {
    if ((PT_REGS_PARM3(ctx) & 0x4) != 0x4)
        return 0;
    if (PT_REGS_PARM1(ctx) <= 0xffffffff)
        return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct mprotect_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    record.p0 = PT_REGS_PARM1(ctx);
    record.p1 = PT_REGS_PARM2(ctx);
    record.p2 = PT_REGS_PARM3(ctx);
    
    mprotect_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// memcpy //
/*
struct memcpy_param {
    u64 ts;
    u32 pid;
    u32 tid;
    u64 p0;
    u64 p1;
    u64 p2;
};
BPF_HASH(memcpy_records, u64, struct memcpy_param);

int memcpy_hook(struct pt_regs *ctx) {
    if (PT_REGS_PARM3(ctx) == 0)
        return 0; // ignore PROT_NONE

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct memcpy_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    record.p0 = PT_REGS_PARM1(ctx);
    record.p1 = PT_REGS_PARM2(ctx);
    record.p2 = PT_REGS_PARM3(ctx);
    
    memcpy_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};
*/

// time //

struct time_param {
    u64 ts;
    u32 pid;
    u32 tid;
};
BPF_HASH(time_records, u64, struct time_param);

int time_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct time_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    
    time_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// gettimeofday //

struct gettimeofday_param {
    u64 ts;
    u32 pid;
    u32 tid;
};
BPF_HASH(gettimeofday_records, u64, struct gettimeofday_param);

int gettimeofday_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct gettimeofday_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    
    gettimeofday_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// do_dlopen (linker) //
/*
struct dlopen_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p0[128];
};
BPF_HASH(dlopen_records, u64, struct dlopen_param);

int dlopen_hook(struct pt_regs *ctx) {
    if (!PT_REGS_PARM1(ctx))
        return 0;
        
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct dlopen_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p0, sizeof(record.p0), (void *)PT_REGS_PARM1(ctx));
    
    dlopen_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};
*/

// JavaVMExt::LoadNativeLibrary (libart) //

struct dlopen_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p0[128];
};
BPF_HASH(dlopen_records, u64, struct dlopen_param);

int dlopen_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct dlopen_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    u64 path_ptr;
    bpf_probe_read(&path_ptr, sizeof(path_ptr), (void *)(PT_REGS_PARM3(ctx) + 0x10));
    bpf_probe_read(&record.p0, sizeof(record.p0), (void *)path_ptr);
    
    if (record.p0[0] == '\\0') // filter
        return 0;
    
    dlopen_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// JavaVMExt::LoadNativeLibrary (libart) //

struct dlopen_ret_param {
    u64 ts;
    u32 pid;
    u32 tid;
};
BPF_HASH(dlopen_ret_records, u64, struct dlopen_ret_param);

int dlopen_ret_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct dlopen_ret_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    
    dlopen_ret_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// art::DexFileLoader::OpenCommon //
/*
struct open_common_param {
    u64 ts;
    u32 pid;
    u32 tid;
    u64 p0;
};
BPF_HASH(open_common_records, u64, struct open_common_param);

int open_common_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct open_common_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    record.p0 = PT_REGS_PARM1(ctx);
    
    open_common_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};
*/

// CompactDexFile::CompactDexFile //
/*
struct compact_init_param {
    u64 ts;
    u32 pid;
    u32 tid;
    u64 p0;
    u64 p1;
    u64 p2;
    u64 p3;
};
BPF_HASH(compact_init_records, u64, struct compact_init_param);

int compact_init_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct compact_init_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    record.p0 = PT_REGS_PARM1(ctx);
    record.p1 = PT_REGS_PARM2(ctx);
    record.p2 = PT_REGS_PARM3(ctx);
    record.p3 = PT_REGS_PARM4(ctx);
    
    compact_init_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};
*/

// DexFile::DexFile //

struct dexfile_init_param {
    u64 ts;
    u32 pid;
    u32 tid;
    u64 p1; // const uint8_t* base
    // u32 p2; // size_t size
    // u64 p5; 
    char p5[128]; // const std::string&
};
BPF_HASH(dexfile_init_records, u64, struct dexfile_init_param);

int dexfile_init_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct dexfile_init_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    record.p1 = PT_REGS_PARM2(ctx);
    // record.p2 = PT_REGS_PARM3(ctx);
    // bpf_probe_read(&record.p5, sizeof(record.p5), (void *)(PT_REGS_PARM6(ctx) + 0x10));
    u64 location_ptr;
    bpf_probe_read(&location_ptr, sizeof(location_ptr), (void *)(PT_REGS_PARM6(ctx) + 0x10));
    bpf_probe_read(&record.p5, sizeof(record.p5), (void *)location_ptr);
    
    if (record.p5[0] == '\\0') // filter
        return 0;
    
    dexfile_init_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// JniMethodStart //
/*
struct jni_start_param {
    u64 ts;
    u32 pid;
    u32 tid;
};
BPF_HASH(jni_start_records, u64, struct jni_start_param);

// -->>

struct reg {
    u64 ts;
    u32 pid;
    u32 tid;
    u64 x0;
    u64 x1;
    u64 x2;
    u64 x3;
    u64 x4;
    u64 x5;
    u64 x6;
    u64 x7;
    u64 x8;
    u64 x9;
    u64 x10;
    u64 x11;
    u64 x12;
    u64 x13;
    u64 x14;
    u64 x15;
    u64 x16;
    u64 x17;
    u64 x18;
    u64 x19;
    u64 x20;
    u64 x21;
    u64 x22;
    u64 x23;
    u64 x24;
    u64 x25;
    u64 x26;
    u64 x27;
    u64 x28;
    u64 x29;
    u64 x30;
    u64 sp;
    u64 pc;
    u64 pstate;
};

struct libc_rx {
    char buf[0xd2000];
};
struct libc_r {
    char buf[0x6000];
};
struct libc_rw {
    char buf[0x2000];
};

BPF_ARRAY(reg_records, struct reg, 1);
BPF_ARRAY(libc_r_records, struct libc_r, 1);
BPF_ARRAY(libc_rw_records, struct libc_rw, 1);
BPF_ARRAY(libc_rx_records, struct libc_rx, 1);

// <<--

int jni_start_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct jni_start_param param = {};
    
    param.ts = bpf_ktime_get_ns();
    param.pid = pid;
    param.tid = tid;
    
    jni_start_records.lookup_or_init(&param.ts, &param);
    
    // -->>
    
    int index = 0;
    
    struct reg *record = reg_records.lookup(&index);
    if (record == NULL)
        return 0;
    record->ts = bpf_ktime_get_ns();
    record->pid = pid;
    record->tid = tid;
    record->x0 = ((struct user_pt_regs*) ctx)->regs[0];
    record->x1 = ((struct user_pt_regs*) ctx)->regs[1];
    record->x2 = ((struct user_pt_regs*) ctx)->regs[2];
    record->x3 = ((struct user_pt_regs*) ctx)->regs[3];
    record->x4 = ((struct user_pt_regs*) ctx)->regs[4];
    record->x5 = ((struct user_pt_regs*) ctx)->regs[5];
    record->x6 = ((struct user_pt_regs*) ctx)->regs[6];
    record->x7 = ((struct user_pt_regs*) ctx)->regs[7];
    record->x8 = ((struct user_pt_regs*) ctx)->regs[8];
    record->x9 = ((struct user_pt_regs*) ctx)->regs[9];
    record->x10 = ((struct user_pt_regs*) ctx)->regs[10];
    record->x11 = ((struct user_pt_regs*) ctx)->regs[11];
    record->x12 = ((struct user_pt_regs*) ctx)->regs[12];
    record->x13 = ((struct user_pt_regs*) ctx)->regs[13];
    record->x14 = ((struct user_pt_regs*) ctx)->regs[14];
    record->x15 = ((struct user_pt_regs*) ctx)->regs[15];
    record->x16 = ((struct user_pt_regs*) ctx)->regs[16];
    record->x17 = ((struct user_pt_regs*) ctx)->regs[17];
    record->x18 = ((struct user_pt_regs*) ctx)->regs[18];
    record->x19 = ((struct user_pt_regs*) ctx)->regs[19];
    record->x20 = ((struct user_pt_regs*) ctx)->regs[20];
    record->x21 = ((struct user_pt_regs*) ctx)->regs[21];
    record->x22 = ((struct user_pt_regs*) ctx)->regs[22];
    record->x23 = ((struct user_pt_regs*) ctx)->regs[23];
    record->x24 = ((struct user_pt_regs*) ctx)->regs[24];
    record->x25 = ((struct user_pt_regs*) ctx)->regs[25];
    record->x26 = ((struct user_pt_regs*) ctx)->regs[26];
    record->x27 = ((struct user_pt_regs*) ctx)->regs[27];
    record->x28 = ((struct user_pt_regs*) ctx)->regs[28];
    record->x29 = ((struct user_pt_regs*) ctx)->regs[29];
    record->x30 = ((struct user_pt_regs*) ctx)->regs[30];
    record->sp = ((struct user_pt_regs*) ctx)->sp;
    record->pc = ((struct user_pt_regs*) ctx)->pc;
    record->pstate = ((struct user_pt_regs*) ctx)->pstate;
    
    struct libc_rx *data_libc_rx = libc_rx_records.lookup(&index);
    if (data_libc_rx == NULL)
        return 0;
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    bpf_probe_read(&(data_libc_rx->buf), sizeof(data_libc_rx->buf), (void *)0x7dde280000);
    
    struct libc_r *data_libc_r = libc_r_records.lookup(&index);
    if (data_libc_r == NULL)
        return 0;
    bpf_probe_read(&(data_libc_r->buf), sizeof(data_libc_r->buf), (void *)0x7dde36a000);
    
    struct libc_r *data_libc_rw = libc_r_records.lookup(&index);
    if (data_libc_rw == NULL)
        return 0;
    bpf_probe_read(&(data_libc_rw->buf), sizeof(data_libc_rw->buf), (void *)0x7dde370000);
    
    // <<--
    
    return 0;
};
*/

// JniMethodFastStart //
/*
struct jni_faststart_param {
    u64 ts;
    u32 pid;
    u32 tid;
};
BPF_HASH(jni_faststart_records, u64, struct jni_faststart_param);

int jni_faststart_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct jni_faststart_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    
    jni_faststart_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};
*/

// JniMethodEnd //
/*
struct jni_end_param {
    u64 ts;
    u32 pid;
    u32 tid;
};
BPF_HASH(jni_end_records, u64, struct jni_end_param);

int jni_end_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct jni_end_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    
    jni_end_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};
*/

// JniMethodFastEnd //
/*
struct jni_fastend_param {
    u64 ts;
    u32 pid;
    u32 tid;
};
BPF_HASH(jni_fastend_records, u64, struct jni_fastend_param);

int jni_fastend_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct jni_fastend_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    
    jni_fastend_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};
*/

// JniMethodEndSynchronized //
/*
struct jni_endsynchronized_param {
    u64 ts;
    u32 pid;
    u32 tid;
};
BPF_HASH(jni_endsynchronized_records, u64, struct jni_endsynchronized_param);

int jni_endsynchronized_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct jni_endsynchronized_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    
    jni_endsynchronized_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};
*/

// JniMethodEndWithReferenceHandleResult //
/*
struct jni_endreference_param {
    u64 ts;
    u32 pid;
    u32 tid;
};
BPF_HASH(jni_endreference_records, u64, struct jni_endreference_param);

int jni_endreference_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct jni_endreference_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    
    jni_endreference_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};
*/

// JNI_start //

struct jni_start_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p0[128];
};
BPF_HASH(jni_start_records, u64, struct jni_start_param);

int jni_start_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct jni_start_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p0, sizeof(record.p0), (void *)PT_REGS_PARM1(ctx));
    
    if (record.p0[0] == '\\0') // filter
        return 0;
    
    jni_start_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// JNI_end //

struct jni_end_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p0[128];
};
BPF_HASH(jni_end_records, u64, struct jni_end_param);

int jni_end_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct jni_end_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p0, sizeof(record.p0), (void *)PT_REGS_PARM1(ctx));
    
    if (record.p0[0] == '\\0') // filter
        return 0;
    
    jni_end_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// VMDebug_isDebuggerConnected //

struct jdwp_debug_param {
    u64 ts;
    u32 pid;
    u32 tid;
};
BPF_HASH(jdwp_debug_records, u64, struct jdwp_debug_param);

int jdwp_debug_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct jdwp_debug_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    
    jdwp_debug_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// JNI_NewString //

struct new_string_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p1[128];
};
BPF_HASH(new_string_records, u64, struct new_string_param);

int new_string_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct new_string_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p1, sizeof(record.p1), (void *)PT_REGS_PARM2(ctx));
    
    if (record.p1[0] == '\\0') // filter
        return 0;
    if (record.p1[1] == '\\0') // filter
        return 0;
    
    new_string_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// JNI_NewStringUTF //

struct new_stringutf_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p1[128];
};
BPF_HASH(new_stringutf_records, u64, struct new_stringutf_param);

int new_stringutf_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct new_stringutf_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p1, sizeof(record.p1), (void *)PT_REGS_PARM2(ctx));
    
    if (record.p1[0] == '\\0') // filter
        return 0;
    if (record.p1[1] == '\\0') // filter
        return 0;
    
    new_stringutf_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// JNI_FindClass //

struct find_class_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p1[128];
};
BPF_HASH(find_class_records, u64, struct find_class_param);

int find_class_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct find_class_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p1, sizeof(record.p1), (void *)PT_REGS_PARM2(ctx));
    
    if (record.p1[0] == '\\0') // filter
        return 0;
    
    find_class_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// JNI_FindMethodId //

struct find_methodid_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p2[128];
};
BPF_HASH(find_methodid_records, u64, struct find_methodid_param);

int find_methodid_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct find_methodid_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p2, sizeof(record.p2), (void *)PT_REGS_PARM3(ctx));
    
    if (record.p2[0] == '\\0') // filter
        return 0;
    
    find_methodid_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// JNI_FindFieldId //

struct find_fieldid_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p2[128];
};
BPF_HASH(find_fieldid_records, u64, struct find_fieldid_param);

int find_fieldid_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct find_fieldid_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p2, sizeof(record.p2), (void *)PT_REGS_PARM3(ctx));
    
    if (record.p2[0] == '\\0') // filter
        return 0;
    
    find_fieldid_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// InvokeWithArgArray //

struct jni_invoke_param {
    u64 ts;
    u32 pid;
    u32 tid;
    char p0[128];
};
BPF_HASH(jni_invoke_records, u64, struct jni_invoke_param);

int jni_invoke_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct jni_invoke_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    bpf_probe_read(&record.p0, sizeof(record.p0), (void *)PT_REGS_PARM1(ctx));
    
    if (record.p0[0] == '\\0') // filter
        return 0;
    
    jni_invoke_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// connect IPv4 //

struct connect4_param {
    u64 ts;
    u32 pid;
    u32 tid;
    u32 daddr;
    u16 dport;
};
BPF_HASH(connect4_records, u64, struct connect4_param);

int connect4_hook(struct pt_regs *ctx) {
	u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();
    
    struct connect4_param record = {};
    
    record.ts = bpf_ktime_get_ns();
	record.pid = pid;
    record.tid = tid;
    
    u64 struct_ptr = PT_REGS_PARM2(ctx);
    bpf_probe_read(&record.dport, sizeof(record.dport), (void *)(struct_ptr + 0x2));
    bpf_probe_read(&record.daddr, sizeof(record.daddr), (void *)(struct_ptr + 0x4));
	
	connect4_records.lookup_or_init(&record.ts, &record);
	
	return 0;
};

// cacheflush //
/*
struct cacheflush_param {
    u64 ts;
    u32 pid;
    u32 tid;
    // u32 no;
    u64 saddr;
    u64 eaddr;
};
BPF_HASH(cacheflush_records, u64, struct cacheflush_param);

int cacheflush_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    // if (pid < 1000)
        // return 0;
    u32 tid = bpf_get_current_pid_tgid();
    
    struct cacheflush_param record = {};
    
    record.ts = bpf_ktime_get_ns();
	record.pid = pid;
    record.tid = tid;
    
    struct pt_regs regs = {};
    bpf_probe_read(&regs, sizeof(regs), (void *)PT_REGS_PARM1(ctx));
    
    // record.no = regs.regs[7];
    
    if (regs.regs[7] != 0x0f0002)
        return 0;
    
    record.saddr = regs.regs[0];
    record.eaddr = regs.regs[1];
    
    cacheflush_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};
*/

// fork //

struct fork_return_param {
    u64 ts;
    u32 pid;
    u32 tid;
    u32 ret;
};
BPF_HASH(fork_return_records, u64, struct fork_return_param);

int fork_return_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct fork_return_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    record.ret = PT_REGS_RC(ctx);
    
    fork_return_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// sys_brk //

struct sys_brk_param {
    u64 ts;
    u32 pid;
    u32 tid;
    u64 p0;
};
BPF_HASH(sys_brk_records, u64, struct sys_brk_param);

int sys_brk_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct sys_brk_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    record.p0 = PT_REGS_PARM1(ctx);
    
    sys_brk_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

// sys_mmap //

struct sys_mmap_enter_param {
    u64 ts;
    u32 pid;
    u32 tid;
    u64 p0;
    u64 p1;
    u32 p2;
};
BPF_HASH(sys_mmap_enter_records, u64, struct sys_mmap_enter_param);

int sys_mmap_enter_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct sys_mmap_enter_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    record.p0 = PT_REGS_PARM1(ctx);
    record.p1 = PT_REGS_PARM2(ctx);
    record.p2 = PT_REGS_PARM3(ctx);
    
    sys_mmap_enter_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

struct sys_mmap_return_param {
    u64 ts;
    u32 pid;
    u32 tid;
    u64 ret;
};
BPF_HASH(sys_mmap_return_records, u64, struct sys_mmap_return_param);

int sys_mmap_return_hook(struct pt_regs *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid < 1000)
        return 0;
    u32 tid = bpf_get_current_pid_tgid();

    struct sys_mmap_return_param record = {};
    
    record.ts = bpf_ktime_get_ns();
    record.pid = pid;
    record.tid = tid;
    record.ret = PT_REGS_RC(ctx);
    
    sys_mmap_return_records.lookup_or_init(&record.ts, &record);
    
    return 0;
};

""")

b.attach_uprobe(name="/system/lib64/libc.so", sym="strcmp", fn_name="strcmp_hook")
b.attach_uprobe(name="/system/lib64/libc.so", sym="strcasecmp", fn_name="strcasecmp_hook")
b.attach_uprobe(name="/system/lib64/libc.so", sym="strncmp", fn_name="strncmp_hook")
b.attach_uprobe(name="/system/lib64/libc.so", sym="strncasecmp", fn_name="strncasecmp_hook")
b.attach_uprobe(name="/system/lib64/libc.so", sym="strstr", fn_name="strstr_hook")
b.attach_uprobe(name="/system/lib64/libc.so", sym="open", fn_name="open_hook")
b.attach_uprobe(name="/system/lib64/libc.so", sym="openat", fn_name="openat_hook")
b.attach_uprobe(name="/system/lib64/libc.so", sym="fopen", fn_name="fopen_hook")
b.attach_uprobe(name="/system/lib64/libc.so", sym="write", fn_name="write_hook")
b.attach_uprobe(name="/system/lib64/libc.so", sym="access", fn_name="access_hook")
b.attach_uprobe(name="/system/lib64/libc.so", sym="stat", fn_name="stat_hook")
b.attach_uprobe(name="/system/lib64/libc.so", sym="__system_property_get", fn_name="sys_property_get_hook")

b.attach_uprobe(name="/system/lib64/libc.so", sym="popen", fn_name="popen_hook")
b.attach_uprobe(name="/system/lib64/libc.so", sym="execl", fn_name="execl_hook")
b.attach_uprobe(name="/system/lib64/libc.so", sym="execle", fn_name="execle_hook")
b.attach_uprobe(name="/system/lib64/libc.so", sym="execlp", fn_name="execlp_hook")
b.attach_uprobe(name="/system/lib64/libc.so", sym="execv", fn_name="execv_hook")
b.attach_uprobe(name="/system/lib64/libc.so", sym="execvp", fn_name="execvp_hook")
b.attach_uprobe(name="/system/lib64/libc.so", sym="execvpe", fn_name="execvpe_hook")

b.attach_uprobe(name="/system/lib64/libc.so", sym="mmap", fn_name="mmap_enter_hook")
b.attach_uretprobe(name="/system/lib64/libc.so", sym="mmap", fn_name="mmap_return_hook")
b.attach_uprobe(name="/system/lib64/libc.so", sym="mprotect", fn_name="mprotect_hook")
# b.attach_uprobe(name="/system/lib64/libc.so", sym="memcpy", fn_name="memcpy_hook")

b.attach_kprobe(event="sys_brk", fn_name="sys_brk_hook")
b.attach_kprobe(event="sys_mmap", fn_name="sys_mmap_enter_hook")
b.attach_kretprobe(event="sys_mmap", fn_name="sys_mmap_return_hook")

# b.attach_uprobe(name="/system/lib64/libc.so", sym="time", fn_name="time_hook")
# b.attach_uprobe(name="/system/lib64/libc.so", sym="gettimeofday", fn_name="gettimeofday_hook")

# b.attach_uprobe(name="/system/bin/linker64", addr=0x17f30, fn_name="dlopen_hook")
b.attach_uprobe(name="/system/lib64/libart.so", addr=0x2c1d48, fn_name="dlopen_hook")
b.attach_uprobe(name="/system/lib64/libart.so", addr=0x2c2b54, fn_name="dlopen_ret_hook")

# b.attach_uprobe(name="/system/lib64/libdexfile.so", sym="_ZN3art13DexFileLoader10OpenCommonEPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileEbbPS9_NS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISH_EEEEPNS0_12VerifyResultE", fn_name="open_common_hook")
# b.attach_uprobe(name="/system/lib64/libdexfile.so", sym="_ZN3art14CompactDexFileC2EPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileENS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISG_EEEE", fn_name="compact_init_hook")
# b.attach_uprobe(name="/system/lib64/libdexfile.so", sym="_ZN3art7DexFileC2EPKhmS2_mRKNSt3__112basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEEjPKNS_10OatDexFileENS3_10unique_ptrINS_16DexFileContainerENS3_14default_deleteISG_EEEEb", fn_name="dexfile_init_hook")
b.attach_uprobe(name="/system/lib64/libdexfile.so", addr=0xdda8, fn_name="dexfile_init_hook")

'''
b.attach_uprobe(name="/system/lib64/libart.so", addr=0x4ec898, fn_name="jni_start_hook")
b.attach_uprobe(name="/system/lib64/libart.so", addr=0x4ec884, fn_name="jni_faststart_hook")
b.attach_uprobe(name="/system/lib64/libart.so", addr=0x4eca88, fn_name="jni_end_hook")
b.attach_uprobe(name="/system/lib64/libart.so", addr=0x4ecd94, fn_name="jni_fastend_hook")
b.attach_uprobe(name="/system/lib64/libart.so", addr=0x4ece3c, fn_name="jni_endsynchronized_hook")
b.attach_uprobe(name="/system/lib64/libart.so", addr=0x4ed0e0, fn_name="jni_endreference_hook")
'''
b.attach_uprobe(name="/system/lib64/libart.so", addr=0x4efaf4, fn_name="jni_start_hook")
b.attach_uprobe(name="/system/lib64/libart.so", addr=0x4f03d8, fn_name="jni_end_hook")

b.attach_uprobe(name="/system/lib64/libart.so", addr=0x3a53b4, fn_name="jdwp_debug_hook")
                                      
b.attach_uprobe(name="/system/lib64/libart.so", addr=0x302ca8, fn_name="find_class_hook")
b.attach_uprobe(name="/system/lib64/libart.so", addr=0x35e894, fn_name="find_methodid_hook")
b.attach_uprobe(name="/system/lib64/libart.so", addr=0x35ece8, fn_name="find_fieldid_hook")
b.attach_uprobe(name="/system/lib64/libart.so", addr=0x436770, fn_name="jni_invoke_hook")
b.attach_uprobe(name="/system/lib64/libart.so", addr=0x3432d4, fn_name="new_string_hook")
b.attach_uprobe(name="/system/lib64/libart.so", addr=0x344784, fn_name="new_stringutf_hook")

b.attach_uprobe(name="/system/lib64/libc.so", sym="connect", fn_name="connect4_hook")
b.attach_uretprobe(name="/system/lib64/libc.so", sym="fork", fn_name="fork_return_hook")

# b.attach_kprobe(event="do_ni_syscall", fn_name="cacheflush_hook")
# b.attach_kprobe(event="compat_arm_syscall", fn_name="cacheflush_hook")

# header
print("Tracing for 30s ...")

# sleep until Ctrl-C
try:
    sleep(30) # sleep(30)
    # sleep(12*60*60)
except KeyboardInterrupt:
    pass

# print output

sys.stdout = open("/home/ebpf_log.txt", "w") # redirect to a file

print("## strcmp ##")
print("%s %s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0", "P1"))
strcmp_records = b.get_table("strcmp_records")
for ts, record in sorted(strcmp_records.items(), key=lambda strcmp_records: strcmp_records[1].ts):
    print("[strcmp] %d,%d,%d,%s,%s" % (record.ts, record.pid, record.tid, record.p0.encode('string-escape'), record.p1.encode('string-escape')))

print("## strcasecmp ##")
print("%s %s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0", "P1"))
strcasecmp_records = b.get_table("strcasecmp_records")
for ts, record in sorted(strcasecmp_records.items(), key=lambda strcasecmp_records: strcasecmp_records[1].ts):
    print("[strcasecmp] %d,%d,%d,%s,%s" % (record.ts, record.pid, record.tid, record.p0.encode('string-escape'), record.p1.encode('string-escape')))

print("## strncmp ##")
print("%s %s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0", "P1"))
strncmp_records = b.get_table("strncmp_records")
for ts, record in sorted(strncmp_records.items(), key=lambda strncmp_records: strncmp_records[1].ts):
    print("[strncmp] %d,%d,%d,%s,%s" % (record.ts, record.pid, record.tid, record.p0.encode('string-escape'), record.p1.encode('string-escape')))
    
print("## strncasecmp ##")
print("%s %s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0", "P1"))
strncasecmp_records = b.get_table("strncasecmp_records")
for ts, record in sorted(strncasecmp_records.items(), key=lambda strncasecmp_records: strncasecmp_records[1].ts):
    print("[strncasecmp] %d,%d,%d,%s,%s" % (record.ts, record.pid, record.tid, record.p0.encode('string-escape'), record.p1.encode('string-escape')))
    
print("## strstr ##")
print("%s %s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0", "P1"))
strstr_records = b.get_table("strstr_records")
for ts, record in sorted(strstr_records.items(), key=lambda strstr_records: strstr_records[1].ts):
    print("[strstr] %d,%d,%d,%s,%s" % (record.ts, record.pid, record.tid, record.p0.encode('string-escape'), record.p1.encode('string-escape')))
    
print("## open ##")
print("%s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0"))
open_records = b.get_table("open_records")
for ts, record in sorted(open_records.items(), key=lambda open_records: open_records[1].ts):
    print("[open] %d,%d,%d,%s" % (record.ts, record.pid, record.tid, record.p0.encode('string-escape')))
    
print("## openat ##")
print("%s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P1"))
openat_records = b.get_table("openat_records")
for ts, record in sorted(openat_records.items(), key=lambda openat_records: openat_records[1].ts):
    print("[openat] %d,%d,%d,%s" % (record.ts, record.pid, record.tid, record.p1.encode('string-escape')))
    
print("## fopen ##")
print("%s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0"))
fopen_records = b.get_table("fopen_records")
for ts, record in sorted(fopen_records.items(), key=lambda fopen_records: fopen_records[1].ts):
    print("[fopen] %d,%d,%d,%s" % (record.ts, record.pid, record.tid, record.p0.encode('string-escape')))

print("## write ##")
print("%s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P2"))
write_records = b.get_table("write_records")
for ts, record in sorted(write_records.items(), key=lambda write_records: write_records[1].ts):
    print("[write] %d,%d,%d,%d" % (record.ts, record.pid, record.tid, record.p2))

print("## access ##")
print("%s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0"))
access_records = b.get_table("access_records")
for ts, record in sorted(access_records.items(), key=lambda access_records: access_records[1].ts):
    print("[access] %d,%d,%d,%s" % (record.ts, record.pid, record.tid, record.p0.encode('string-escape')))
    
print("## stat ##")
print("%s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0"))
stat_records = b.get_table("stat_records")
for ts, record in sorted(stat_records.items(), key=lambda stat_records: stat_records[1].ts):
    print("[stat] %d,%d,%d,%s" % (record.ts, record.pid, record.tid, record.p0.encode('string-escape')))
    
print("## __system_property_get ##")
print("%s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0"))
sys_property_get_records = b.get_table("sys_property_get_records")
for ts, record in sorted(sys_property_get_records.items(), key=lambda sys_property_get_records: sys_property_get_records[1].ts):
    print("[__system_property_get] %d,%d,%d,%s" % (record.ts, record.pid, record.tid, record.p0.encode('string-escape')))
    
print("## popen ##")
print("%s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0"))
popen_records = b.get_table("popen_records")
for ts, record in sorted(popen_records.items(), key=lambda popen_records: popen_records[1].ts):
    print("[popen] %d,%d,%d,%s" % (record.ts, record.pid, record.tid, record.p0.encode('string-escape')))
    
print("## execl ##")
print("%s %s %s %s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0", "P1", "P2", "P3"))
execl_records = b.get_table("execl_records")
for ts, record in sorted(execl_records.items(), key=lambda execl_records: execl_records[1].ts):
    print("[execl] %d,%d,%d,%s,%s,%s,%s" % (record.ts, record.pid, record.tid, record.p0.encode('string-escape'), record.p1.encode('string-escape'), record.p2.encode('string-escape'), record.p3.encode('string-escape')))

print("## execle ##")
print("%s %s %s %s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0", "P1", "P2", "P3"))
execle_records = b.get_table("execle_records")
for ts, record in sorted(execle_records.items(), key=lambda execle_records: execle_records[1].ts):
    print("[execle] %d,%d,%d,%s,%s,%s,%s" % (record.ts, record.pid, record.tid, record.p0.encode('string-escape'), record.p1.encode('string-escape'), record.p2.encode('string-escape'), record.p3.encode('string-escape')))

print("## execlp ##")
print("%s %s %s %s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0", "P1", "P2", "P3"))
execlp_records = b.get_table("execlp_records")
for ts, record in sorted(execlp_records.items(), key=lambda execlp_records: execlp_records[1].ts):
    print("[execlp] %d,%d,%d,%s,%s,%s,%s" % (record.ts, record.pid, record.tid, record.p0.encode('string-escape'), record.p1.encode('string-escape'), record.p2.encode('string-escape'), record.p3.encode('string-escape')))

print("## execv ##")
print("%s %s %s %s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0", "P1", "P2", "P3"))
execv_records = b.get_table("execv_records")
for ts, record in sorted(execv_records.items(), key=lambda execv_records: execv_records[1].ts):
    print("[execv] %d,%d,%d,%s,%s,%s,%s" % (record.ts, record.pid, record.tid, record.p0.encode('string-escape'), record.p1.encode('string-escape'), record.p2.encode('string-escape'), record.p3.encode('string-escape')))

print("## execvp ##")
print("%s %s %s %s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0", "P1", "P2", "P3"))
execvp_records = b.get_table("execvp_records")
for ts, record in sorted(execvp_records.items(), key=lambda execvp_records: execvp_records[1].ts):
    print("[execvp] %d,%d,%d,%s,%s,%s,%s" % (record.ts, record.pid, record.tid, record.p0.encode('string-escape'), record.p1.encode('string-escape'), record.p2.encode('string-escape'), record.p3.encode('string-escape')))

print("## execvpe ##")
print("%s %s %s %s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0", "P1", "P2", "P3"))
execvpe_records = b.get_table("execvpe_records")
for ts, record in sorted(execvpe_records.items(), key=lambda execvpe_records: execvpe_records[1].ts):
    print("[execvpe] %d,%d,%d,%s,%s,%s,%s" % (record.ts, record.pid, record.tid, record.p0.encode('string-escape'), record.p1.encode('string-escape'), record.p2.encode('string-escape'), record.p3.encode('string-escape')))

print("## mmap ==>> enter ##")
print("%s %s %s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0", "P1", "P2"))
mmap_enter_records = b.get_table("mmap_enter_records")
for ts, record in sorted(mmap_enter_records.items(), key=lambda mmap_enter_records: mmap_enter_records[1].ts):
    print("[mmap-start] %d,%d,%d,%x,%d,%d" % (record.ts, record.pid, record.tid, record.p0, record.p1, record.p2))

print("## mmap <<== return ##")
print("%s %s %s %s" % ("TIMESTAMP", "PID", "TID", "RET"))
mmap_return_records = b.get_table("mmap_return_records")
for ts, record in sorted(mmap_return_records.items(), key=lambda mmap_return_records: mmap_return_records[1].ts):
    print("[mmap-end] %d,%d,%d,%x" % (record.ts, record.pid, record.tid, record.ret))

print("## mprotect ##")
print("%s %s %s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0", "P1", "P2"))
mprotect_records = b.get_table("mprotect_records")
for ts, record in sorted(mprotect_records.items(), key=lambda mprotect_records: mprotect_records[1].ts):
    print("[mprotect] %d,%d,%d,%x,%d,%d" % (record.ts, record.pid, record.tid, record.p0, record.p1, record.p2))

'''    
print("## memcpy ##")
print("%s %s %s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0", "P1", "P2"))
memcpy_records = b.get_table("memcpy_records")
for ts, record in sorted(memcpy_records.items(), key=lambda memcpy_records: memcpy_records[1].ts):
    print("[memcpy] %d,%d,%d,%x,%x,%d" % (record.ts, record.pid, record.tid record.p0, record.p1, record.p2))
'''

print("## sys_brk ##")
print("%s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0"))
sys_brk_records = b.get_table("sys_brk_records")
for ts, record in sorted(sys_brk_records.items(), key=lambda sys_brk_records: sys_brk_records[1].ts):
    print("[sys_brk] %d,%d,%d,%x" % (record.ts, record.pid, record.tid, record.p0))

print("## sys_mmap ==>> enter ##")
print("%s %s %s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0", "P1", "P2"))
sys_mmap_enter_records = b.get_table("sys_mmap_enter_records")
for ts, record in sorted(sys_mmap_enter_records.items(), key=lambda sys_mmap_enter_records: sys_mmap_enter_records[1].ts):
    print("[sys_mmap-start] %d,%d,%d,%x,%d,%d" % (record.ts, record.pid, record.tid, record.p0, record.p1, record.p2))

print("## sys_mmap <<== return ##")
print("%s %s %s %s" % ("TIMESTAMP", "PID", "TID", "RET"))
sys_mmap_return_records = b.get_table("sys_mmap_return_records")
for ts, record in sorted(sys_mmap_return_records.items(), key=lambda sys_mmap_return_records: sys_mmap_return_records[1].ts):
    print("[sys_mmap-end] %d,%d,%d,%x" % (record.ts, record.pid, record.tid, record.ret))

'''
print("## time ##")
print("%s %s %s" % ("TIMESTAMP", "PID", "TID"))
time_records = b.get_table("time_records")
for ts, record in sorted(time_records.items(), key=lambda time_records: time_records[1].ts):
    print("[time] %d,%d,%d" % (record.ts, record.pid, record.tid))
'''
   
'''    
print("## gettimeofday ##")
print("%s %s %s" % ("TIMESTAMP", "PID", "TID"))
gettimeofday_records = b.get_table("gettimeofday_records")
for ts, record in sorted(gettimeofday_records.items(), key=lambda gettimeofday_records: gettimeofday_records[1].ts):
    print("[gettimeofday] %d,%d,%d" % (record.ts, record.pid, record.tid))
'''

print("## dlopen ==>> enter ##")
print("%s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0"))
dlopen_records = b.get_table("dlopen_records")
for ts, record in sorted(dlopen_records.items(), key=lambda dlopen_records: dlopen_records[1].ts):
    print("[dlopen-start] %d,%d,%d,%s" % (record.ts, record.pid, record.tid, record.p0.encode('string-escape')))
    
print("## dlopen <<== return ##")
print("%s %s %s" % ("TIMESTAMP", "PID", "TID"))
dlopen_ret_records = b.get_table("dlopen_ret_records")
for ts, record in sorted(dlopen_ret_records.items(), key=lambda dlopen_ret_records: dlopen_ret_records[1].ts):
    print("[dlopen-end] %d,%d,%d" % (record.ts, record.pid, record.tid))

'''
print("## art::DexFileLoader::OpenCommon ##")
print("%s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0"))
open_common_records = b.get_table("open_common_records")
for ts, record in sorted(open_common_records.items(), key=lambda open_common_records: open_common_records[1].ts):
    print("[??] %d,%d,%d,%s" % (record.ts, record.pid, record.tid, record.p0.encode('string-escape')))
'''

''' 
print("## CompactDexFile::CompactDexFile ##")
print("%s %s %s %s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0", "P1", "P2", "P3"))
compact_init_records = b.get_table("compact_init_records")
for ts, record in sorted(compact_init_records.items(), key=lambda compact_init_records: compact_init_records[1].ts):
    print("[??] %d,%d,%d,%x,%d,%x,%d" % (record.ts, record.pid, record.tid, record.p0, record.p1, record.p2, record.p3))
'''
 
print("## DexFile::DexFile ##")
print("%s %s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P1", "P5"))
dexfile_init_records = b.get_table("dexfile_init_records")
for ts, record in sorted(dexfile_init_records.items(), key=lambda dexfile_init_records: dexfile_init_records[1].ts):
    print("[DexFile] %d,%d,%d,%x,%s" % (record.ts, record.pid, record.tid, record.p1, record.p5.encode('string-escape')))

'''
print("## JniMethodStart ##")
print("%s %s %s" % ("TIMESTAMP", "PID", "TID"))
jni_start_records = b.get_table("jni_start_records")
for ts, record in sorted(jni_start_records.items(), key=lambda jni_start_records: jni_start_records[1].ts):
    print("[JNI-start] %d,%d,%d" % (record.ts, record.pid, record.tid))

print("## JniMethodFastStart ##")
print("%s %s %s" % ("TIMESTAMP", "PID", "TID"))
jni_faststart_records = b.get_table("jni_faststart_records")
for ts, record in sorted(jni_faststart_records.items(), key=lambda jni_faststart_records: jni_faststart_records[1].ts):
    print("[JNI-start] %d,%d,%d" % (record.ts, record.pid, record.tid))

print("## JniMethodEnd ##")
print("%s %s %s" % ("TIMESTAMP", "PID", "TID"))
jni_end_records = b.get_table("jni_end_records")
for ts, record in sorted(jni_end_records.items(), key=lambda jni_end_records: jni_end_records[1].ts):
    print("[JNI-end] %d,%d,%d" % (record.ts, record.pid, record.tid))
    
print("## JniMethodFastEnd ##")
print("%s %s %s" % ("TIMESTAMP", "PID", "TID"))
jni_fastend_records = b.get_table("jni_fastend_records")
for ts, record in sorted(jni_fastend_records.items(), key=lambda jni_fastend_records: jni_fastend_records[1].ts):
    print("[JNI-end] %d,%d,%d" % (record.ts, record.pid, record.tid))

print("## JniMethodEndSynchronized ##")
print("%s %s %s" % ("TIMESTAMP", "PID", "TID"))
jni_endsynchronized_records = b.get_table("jni_endsynchronized_records")
for ts, record in sorted(jni_endsynchronized_records.items(), key=lambda jni_endsynchronized_records: jni_endsynchronized_records[1].ts):
    print("[JNI-end] %d,%d,%d" % (record.ts, record.pid, record.tid))

print("## JniMethodEndWithReferenceHandleResult ##")
print("%s %s %s" % ("TIMESTAMP", "PID", "TID"))
jni_endreference_records = b.get_table("jni_endreference_records")
for ts, record in sorted(jni_endreference_records.items(), key=lambda jni_endreference_records: jni_endreference_records[1].ts):
    print("[JNI-end] %d,%d,%d" % (record.ts, record.pid, record.tid))
'''

print("## JniMethodStart ##")
print("%s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0"))
jni_start_records = b.get_table("jni_start_records")
for ts, record in sorted(jni_start_records.items(), key=lambda jni_start_records: jni_start_records[1].ts):
    print("[JNI-start] %d,%d,%d,%s" % (record.ts, record.pid, record.tid, record.p0.encode('string-escape')))

print("## JniMethodEnd ##")
print("%s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0"))
jni_end_records = b.get_table("jni_end_records")
for ts, record in sorted(jni_end_records.items(), key=lambda jni_end_records: jni_end_records[1].ts):
    print("[JNI-end] %d,%d,%d,%s" % (record.ts, record.pid, record.tid, record.p0.encode('string-escape')))

print("## VMDebug_isDebuggerConnected ##")
print("%s %s %s" % ("TIMESTAMP", "PID", "TID"))
jdwp_debug_records = b.get_table("jdwp_debug_records")
for ts, record in sorted(jdwp_debug_records.items(), key=lambda jdwp_debug_records: jdwp_debug_records[1].ts):
    print("[isDebuggerConnected] %d,%d,%d" % (record.ts, record.pid, record.tid))

print("## JNI_FindClass ##")
print("%s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P1"))
find_class_records = b.get_table("find_class_records")
for ts, record in sorted(find_class_records.items(), key=lambda find_class_records: find_class_records[1].ts):
    print("[FindClass] %d,%d,%d,%s" % (record.ts, record.pid, record.tid, record.p1.encode('string-escape')))

print("## JNI_FindMethodID ##")
print("%s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P2"))
find_methodid_records = b.get_table("find_methodid_records")
for ts, record in sorted(find_methodid_records.items(), key=lambda find_methodid_records: find_methodid_records[1].ts):
    print("[FindMethodID] %d,%d,%d,%s" % (record.ts, record.pid, record.tid, record.p2.encode('string-escape')))

print("## JNI_FindFieldID ##")
print("%s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P2"))
find_fieldid_records = b.get_table("find_fieldid_records")
for ts, record in sorted(find_fieldid_records.items(), key=lambda find_fieldid_records: find_fieldid_records[1].ts):
    print("[FindFieldID] %d,%d,%d,%s" % (record.ts, record.pid, record.tid, record.p2.encode('string-escape')))

print("## JNI_INVOKE ##")
print("%s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0"))
jni_invoke_records = b.get_table("jni_invoke_records")
for ts, record in sorted(jni_invoke_records.items(), key=lambda jni_invoke_records: jni_invoke_records[1].ts):
    print("[InvokeWithArgArray] %d,%d,%d,%s" % (record.ts, record.pid, record.tid, record.p0.encode('string-escape')))

print("## JNI_NewString ##")
print("%s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P1"))
new_string_records = b.get_table("new_string_records")
for ts, record in sorted(new_string_records.items(), key=lambda new_string_records: new_string_records[1].ts):
    print("[NewString] %d,%d,%d,%s" % (record.ts, record.pid, record.tid, record.p1.encode('string-escape')))

print("## JNI_NewStringUTF ##")
print("%s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P1"))
new_stringutf_records = b.get_table("new_stringutf_records")
for ts, record in sorted(new_stringutf_records.items(), key=lambda new_stringutf_records: new_stringutf_records[1].ts):
    print("[NewStringUTF] %d,%d,%d,%s" % (record.ts, record.pid, record.tid, record.p1.encode('string-escape')))

print("## Connect IPv4 ##")
print("%s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P1"))
connect4_records = b.get_table("connect4_records")
for ts, record in sorted(connect4_records.items(), key=lambda connect4_records: connect4_records[1].ts):
    dst_ip = inet_ntop(AF_INET, pack("I", record.daddr)).encode()
    dst_port = unpack('!H', pack('@H', record.dport))[0]
    print("[Connect4] %d,%d,%d,%s:%d" % (record.ts, record.pid, record.tid, dst_ip, dst_port))

'''
print("## cacheflush ##")
print("%s %s %s %s %s" % ("TIMESTAMP", "PID", "TID", "P0", "P1"))
cacheflush_records = b.get_table("cacheflush_records")
for ts, record in sorted(cacheflush_records.items(), key=lambda cacheflush_records: cacheflush_records[1].ts):
    print("[cacheflush] %d,%d,%d,%x,%x" % (record.ts, record.pid, record.tid, record.saddr, record.eaddr))
    # print("[cacheflush] %d,%d,%d,%x" % (record.ts, record.pid, record.tid, record.no))
'''

print("## fork <<== return ##")
print("%s %s %s %s" % ("TIMESTAMP", "PID", "TID", "RET"))
fork_return_records = b.get_table("fork_return_records")
for ts, record in sorted(fork_return_records.items(), key=lambda fork_return_records: fork_return_records[1].ts):
    print("[fork-end] %d,%d,%d,%d" % (record.ts, record.pid, record.tid, record.ret))

sys.stdout.close()
