#!/usr/bin/env python
#
# Copyright 2019 Carter Yagemann
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

from datetime import datetime
from hashlib import sha256
import json
import logging
from optparse import OptionParser, OptionGroup
import os
import shutil
import signal
import sys
import tempfile
from traceback import format_exc

import angr
from angr import sim_options
from angr.calling_conventions import SimRegArg, SimStackArg
import claripy
import IPython
import psutil

import agc
import angretm
import dwarf
from globals_deep import SimStateDeepGlobals
import nprofiler
import hooks
import plugins.detectors
import plugins.hooks
import reporting
import taint
import xed

PROGRAM_VERSION = '0.6.0'
PROGRAM_USAGE = 'Usage: %prog [options] tracer_output_directory'

class CriticalMemoryException(Exception):
    pass

def sigterm_handler(signo, stack_frame):
    """Handle SIGTERM by turning it into a KeyboardInterrupt"""
    raise KeyboardInterrupt()

def parse_timedelta(value, default_suffix='s'):
    """Parses a string representing a time delta that may contain
    one of the following suffixes:
        s - seconds, m - minutes, h - hours

    If no suffix is included, default_suffix is assumed.

    Returns the number of seconds, or None if value is invalid.
    """
    if len(value) < 1:
        return None

    if value[-1] in 'smh':
        suffix = value[-1]
        delta_str = value[:-1]
    else:
        suffix = default_suffix
        delta_str = value

    try:
        delta = int(delta_str)
    except Exception as ex:
        return None

    if suffix == 'm':
        delta *= 60
    elif suffix == 'h':
        delta *= 3600

    return delta

def parse_args():
    """Parses sys.argv."""
    parser = OptionParser(usage=PROGRAM_USAGE,
                          version='ARCUS ' + PROGRAM_VERSION)

    group_analysis = OptionGroup(parser, 'Analysis Options')
    group_analysis.add_option('-p', '--pid', action='store', type='int', default=None,
            help='Specify which task to analyze by PID (default: first occurring)')
    group_analysis.add_option('--api-snapshot', action='store', type='str', default=None,
            help='If trace contains API snapshots, analyze API_SNAPSHOT (example: '
            '"55e912117020-0")')
    group_analysis.add_option('--api-inference', action='store_true', default=False,
            help="If a prototype definition doesn't exist for the API, attempt to infer it")
    group_analysis.add_option('--stop-unsat', action='store_true', default=False,
            help='Stop immediately if active state becomes unsatisfiable')
    group_analysis.add_option('--save-examples', action='store', type='str',  default=None,
            help='When bugs are found, save example inputs to the provided directory')
    group_analysis.add_option('--save-reports', action='store', type='str', default=None,
            help='Save reports as JSON files to provided directory')
    parser.add_option_group(group_analysis)

    group_logging = OptionGroup(parser, 'Logging Options')
    group_logging.add_option('-l', '--logging', action='store', type='int', default=20,
            help='Log level [10-50] (default: 20 - Info)')
    group_logging.add_option('--logging-pt', action='store', type='int', default=20,
            help='Level for simulation manager (default: Info)')
    group_logging.add_option('--logging-taint', action='store', type='int', default=30,
            help='Level for taint (default: Warn)')
    group_logging.add_option('--logging-angr', action='store', type='int', default=40,
            help='Level for Angr (default: Error)')
    group_logging.add_option('--logging-angr-heap', action='store', type='int', default=40,
            help='Level for Angr heap (default: Error)')
    group_logging.add_option('--logging-agc', action='store', type='int', default=30,
            help='Level for Analysis Garbage Collector (default: Warn)')
    group_logging.add_option('--stack-depth', action='store', type='int', default=10,
            help='Max depth to show when printing a stack (default: 10)')
    parser.add_option_group(group_logging)

    group_debug = OptionGroup(parser, 'Debugging Options')
    group_debug.add_option('--disable-detectors', action='store_true', default=False,
            help='Disable all detector plugins')
    group_debug.add_option('--embed-addr', action='store', type='int', default=None,
            help='Start an interactive Python interpreter when the given address is reached '
            '("state" holds the current angr state)')
    group_debug.add_option('--embed-idx', action='store', type='int', default=None,
            help='Start an interactive Python interpreter when the given trace index is reached '
            '("state" holds the current angr state)')
    group_debug.add_option('--override-max-argv', action='store', type='int', default=None,
            help='Override max string length considered for argv during exploration '
                 '(bytes, mostly used for faster unit testing)')
    parser.add_option_group(group_debug)

    options, args = parser.parse_args()

    # input validation
    if len(args) != 1:
        parser.print_help()
        return (None, None)

    return (options, args)

def parse_entry_state_json(project, trace_dir, snapshot_dir, prep_explore=False, override_max_argv=None):
    """Creates an initial state for the trace.

    Keyword Arguments:
    project -- The Angr Project this state is being created for.
    trace_dir -- The trace directory.
    snapshot_dir -- The snapshot directory. Might be the same as trace_dir, or a subdirectory.
    prep_explore -- Tweak entry state in ways that are more likely to expose bugs.
    Only relevant if explorer plugins are going to be used.

    Returns:
    A tuple (state, argv/env dict) or (None, None) if there was an error.
    """
    regs_path = os.path.join(snapshot_dir, 'regs.txt')
    files_path = os.path.join(trace_dir, 'files.json')
    misc_path = os.path.join(snapshot_dir, 'misc.json')

    is_snapshot = not (trace_dir == snapshot_dir)

    # get argv/env state, register states, memory dumps, file dumps and
    # misc data from trace directory
    log.info("Loading regs from: %s", regs_path)
    with open(regs_path, 'r') as ifile:
        regs = {}
        for line in ifile.readlines():
            line = line.strip().split("]")[1].strip()
            name = line.split("=")[0].strip()
            value = int(line.split("=")[1].strip(), 0)
            regs[name] = value
    log.info("Loading misc from: %s", misc_path)
    with open(misc_path, 'r') as ifile:
        misc = json.load(ifile)

    # add options to our initial state
    extra_opts  = {sim_options.SIMPLIFY_CONSTRAINTS, sim_options.SIMPLIFY_EXPRS,
                   sim_options.SIMPLIFY_MEMORY_WRITES, sim_options.SIMPLIFY_REGISTER_WRITES}
    extra_opts |= {sim_options.ALL_FILES_EXIST}
    extra_opts |= {sim_options.LAZY_SOLVES}

    state = project.factory.entry_state(add_options=extra_opts)
    # register deepcopy version of globals plugin for plugins that do not want data shared between states
    state.register_plugin('deep', SimStateDeepGlobals())

    # restore registers
    for reg in regs:
        if not is_snapshot and reg in ['rsp', 'rbp', 'esp', 'ebp']:
            # we made a new stack so symbolic variables could be added,
            # don't point the state back at the original (it doesn't exist anymore)
            continue
        if project.arch.name == 'AMD64' and reg in ['gs_base', 'cs', 'es', 'fs_base', 'ds', 'ss']:
            # Angr doesn't manage these registers for AMD64
            continue
        try:
            setattr(state.regs, reg, regs[reg])
        except:
            log.warn("State does not have register %s" % reg)

    '''
    # we're about to restore memory, but don't want to overwrite relocations because CLE already resolved them
    # to add things like hooks for simulation procedures
    orig_relocs = dict()
    for obj in project.loader.all_objects:
        for reloc in obj.relocs:
            if reloc.symbol is None or reloc.resolvedby is None:
                continue
            gotaddr = reloc.rebased_addr
            gotvalue = project.loader.memory.unpack_word(gotaddr)
            orig_relocs[gotaddr] = gotvalue
    '''

    # restore memory
    mem_dir = os.path.join(snapshot_dir, 'mem/')
    for item in os.listdir(mem_dir):
        fullfp = os.path.join(mem_dir, item)
        base_va = int(item.split('-', 1)[0], 16)
        end_va = base_va + os.path.getsize(fullfp)
        # log.info("Restoring %s at %#x-%#x" % (name, base_va, end_va))

        name = item.split('-', 1)[1][:-4]
        if name == '0':
            name = 'null'

        '''
        if not is_snapshot and name in ['[stack]']:
            # we created a new stack for the analysis, so don't load in the original
            # heap is fine though because our snapshot includes the brk
            continue
        '''

        with open(fullfp, 'rb') as ifile:
            log.debug("Restoring %s at %#x" % (name, base_va))
            state.memory.store(base_va, ifile.read())

    '''
    # restore CLE's relocations
    for gotaddr in orig_relocs:
        gotvalue = orig_relocs[gotaddr]
        if project.arch.bits == 64:
            state.mem[gotaddr].uint64_t = gotvalue
        elif project.arch.bits == 32:
            state.mem[gotaddr].uint32_t = gotvalue
        else:
            log.error("Unsupported architecture: %d" % project.arch.bits)
            sys.exit(1)
    '''

    return state

def summarize_stashes(stashes, pretty_names, reports, loader, stack_depth):
    """Prints the stashes in a human readable format."""
    log.info("Reached Trace End: " + str(len(stashes['traced']) > 0))
    # counts
    for name in stashes:
        if name in pretty_names:
            pretty = pretty_names[name]
        else:
            pretty = name
        stash_size = len(stashes[name])
        if stash_size > 0:
            log.info("%20s: %d" % (pretty, stash_size))

    # reports
    for name in reports:
        if len(reports[name]) < 1:
            continue
        pretty = pretty_names[name]
        log.info("%s Details:" % pretty)
        for state in reports[name]:
            report = reports[name][state]
            report.log_state(stack_depth)

def check_for_vulns(simgr, proj):
    """Checks all active states for signs of vulnerabilities."""
    for name in plugins.detectors.loaded:
        detector = plugins.detectors.loaded[name]
        if detector.active:
            try:
                detector.active = detector.check_for_vulns(simgr, proj)
            except KeyboardInterrupt as ex:
                raise ex
            except:
                log.error("Uncaught exception raised by detector plugin: %s" % format_exc())
                log.error("Disabling buggy plugin")
                buggy_plugins.add(detector.__name__)
                detector.active = False
                continue

            if not isinstance(detector.active, bool):
                log.warn("%s returned invalid response: %s" % (name, str(detector.active)))
                buggy_plugins.add(detector.__name__)
                detector.active = False

def analyze_stash(simgr, trace, stash, detector, reports):
    """Analyzes a single detector stash.

    Do not call this directly, use analyze().
    """
    for state in simgr.stashes[stash]:
        if state in reports:
            continue  # already analyzed

        # create standard parts of report
        report = reporting.BugReport(state)
        report.set_type(detector.pretty_name)
        report.set_plugin(detector.stash_name)

        # hand to detector plugin to fill in bug specific details
        try:
            detector.analyze_state(simgr, trace, state, report)
        except KeyboardInterrupt as ex:
            raise ex
        except:
            log.error("Uncaught exception raised by detector plugin: %s" % format_exc())
            buggy_plugins.add(detector.__name__)

        reports[state] = report

def analyze(simgr, bb_seq, reports=None):
    """Analyze detector plugin stashes and update reports

    Keyword Args:
    simgr -- The simulation manager.
    bb_seq -- A linear sequence of basic block addresses representing the real executed path.
    reports -- A dictionary of reports, keyed by the state the report pertains to. If None, a
    new dictionary is created.

    Returns:
    The reports dictionary.
    """
    if reports is None:
        reports = dict()

    # invoke detectors on their stashes for root cause analysis
    for detector in list(plugins.detectors.loaded.values()):
        if not detector.stash_name in reports:
            reports[detector.stash_name] = dict()
        analyze_stash(simgr, bb_seq, detector.stash_name, detector, reports[detector.stash_name])

    return reports

def save_examples(simgr, argv_bvs, stash_names, output_dir, trace_dir):
    """Save example inputs that can reproduce each of the states in the provided stashes.

    Keyword Args:
    simgr - The simulation manager containing stashes of state.
    argv_bvs - A list of args used when creating the initial state.
    stash_names - A list of the names of the stashes to save.
    output_dir - The directory to save to.
    trace_dir - The trace directory used for analysis.
    """
    if not os.path.exists(output_dir):
        try:
            os.mkdir(output_dir)
        except Exception as ex:
            log.error("Failed to create %s: %s" % (output_dir, str(ex)))
            return
    if not os.path.isdir(output_dir):
        log.error("%s is not a directory" % output_dir)
        return

    log.info("Saving example inputs to %s" % output_dir)

    input_files = None
    files_json = os.path.join(trace_dir, 'files.json')
    if os.path.isfile(files_json):
        with open(files_json, 'r') as ifile:
            input_files = json.load(ifile)['files'].keys()

    uncon_idx = 0  # fallback numbering for if state.addr cannot be evaluated
    for stash_name in stash_names:
        for state in simgr.stashes[stash_name]:
            try:
                state_dir = os.path.join(output_dir, '%s_%x' % (stash_name, state.addr))
            except:
                state_dir = os.path.join(output_dir, "%s_uncon%d" % (stash_name, uncon_idx))
                uncon_idx += 1
            if not os.path.exists(state_dir):
                os.mkdir(state_dir)

            # save concrete argv
            arg_strs = list()
            for arg in argv_bvs:
                if isinstance(arg, str):
                    arg_strs.append('"%s"' % arg)
                elif isinstance(arg, claripy.ast.bv.BV):
                    con = state.solver.eval(arg, cast_to=bytes)
                    arg_strs.append(str(con.rstrip(b"\x00")))

            with open(os.path.join(state_dir, 'argv.txt'), 'w') as ofile:
                ofile.write(' '.join(arg_strs) + "\n")

            # save concrete stdin
            stdin_data = state.posix.stdin.concretize()
            if stdin_data:
                with open(os.path.join(state_dir, 'stdin.txt'), 'w') as ofile:
                    ofile.write("%s\n" % str(stdin_data))

            # save concrete files
            if not input_files is None:
                saved_files = dict()
                for simfn in input_files:
                    try:
                        simdata = state.fs.get(simfn).concretize()
                    except angr.errors.SimUnsatError:
                        log.error("Failed to concretize file: %s" % os.path.basename(simfn))
                        continue
                    simhash = sha256(simdata).hexdigest()
                    ofilepath = os.path.join(state_dir, simhash)
                    with open(ofilepath, 'wb') as ofile:
                        ofile.write(simdata)
                    saved_files[simfn] = {'data': simhash}
                with open(os.path.join(state_dir, 'files.json'), 'w') as ofile:
                    json.dump(saved_files, ofile)

            # save concrete sockets
            if len(state.posix.sockets) > 0:
                sock_dir = os.path.join(state_dir, 'network')
                if not os.path.exists(sock_dir):
                    os.mkdir(sock_dir)
                for socket in state.posix.sockets:
                    name = '_'.join([str(x) for x in socket])
                    odir_in = os.path.join(sock_dir, name + '_in')
                    odir_out = os.path.join(sock_dir, name + '_out')
                    sock_in, sock_out = state.posix.sockets[socket]

                    if not os.path.exists(odir_in):
                        os.mkdir(odir_in)
                    if not os.path.exists(odir_out):
                        os.mkdir(odir_out)

                    for idx, packet in enumerate(sock_in.concretize()):
                        with open(os.path.join(odir_in, "%d.bin" % idx), 'wb') as ofile:
                            ofile.write(packet)
                    for idx, packet in enumerate(sock_out.concretize()):
                        with open(os.path.join(odir_out, "%d.bin" % idx), 'wb') as ofile:
                            ofile.write(packet)

def save_reports(reports, save_dir):
    """Save reports to save_dir as JSON files"""
    if not os.path.exists(save_dir):
        try:
            os.mkdir(save_dir)
        except Exception as ex:
            log.error("Failed to create %s: %s" % (save_dir, str(ex)))
            return
    if not os.path.isdir(save_dir):
        log.error("%s is not a directory" % save_dir)
        return

    log.info("Saving reports to %s" % save_dir)

    for name in reports:
        for idx, state in enumerate(reports[name]):
            report = reports[name][state]
            # note, the possible collision between report names is intentional to
            # make de-duplication very easy!
            json_filename = '%s_%s.json' % (name, report.get_hash())
            json_path = os.path.join(save_dir, json_filename)
            try:
                with open(json_path, 'w') as ofile:
                    ofile.write(report.to_json())
            except Exception as ex:
                log.error("Failed to save %s: %s" % (json_filename, str(ex)))

def set_log_levels(options):
    """Sets all the log levels based on user provided options."""
    logging.getLogger(__name__).setLevel(options.logging)
    logging.getLogger(reporting.__name__).setLevel(options.logging)
    logging.getLogger(hooks.__name__).setLevel(options.logging)
    logging.getLogger(angretm.__name__).setLevel(options.logging_pt)
    logging.getLogger(taint.__name__).setLevel(options.logging_taint)
    logging.getLogger(angr.__name__).setLevel(options.logging_angr)
    logging.getLogger('angr.state_plugins.heap').setLevel(options.logging_angr_heap)
    logging.getLogger(agc.__name__).setLevel(options.logging_agc)
    logging.getLogger(dwarf.__name__).setLevel(options.logging)

    # hook plugins
    for module in list(plugins.hooks.loaded.values()):
        logging.getLogger(module.__name__).setLevel(options.logging)

    # detector plugins
    for module in list(plugins.detectors.loaded.values()):
        logging.getLogger(module.__name__).setLevel(options.logging)

def get_predecessor(tech, index):
    """Helper function to get predecessors by index, ignoring None elements.

    Keyword Arguments:
    tech -- Exploration technique.
    index -- The index to get (e.g., -1 for last predecessor)

    Returns:
    State on success, otherwise None.
    """
    preds = [state for state in tech.predecessors if not state is None]
    try:
        return preds[index]
    except IndexError:
        return None

def debug_embedding_hook(state, options):
    """If the user set any of the embed debugging options, this is where we
    honor them.

    Keyword Arguments:
    state -- The state to check.
    options -- OptionsParser options dictionary.
    """
    global __name__
    global hooked_idx
    should_hook = False
    sym_ip = lambda s: s.solver.symbolic(s._ip)

    if not sym_ip(state) and state.addr == options.embed_addr:
        log.info("Embedding debug shell at requested address: %#x" % options.embed_addr)
        should_hook = True
    elif state.globals['trace_idx'] == options.embed_idx and not hooked_idx:
        log.info("Embedding debug shell at requested trace index: %d" % options.embed_idx)
        # hooked_idx prevents us from rehooking due to trace_idx not advancing
        # (e.g., because of a trace sync)
        hooked_idx = True
        should_hook = True

    if should_hook:
        # during initialization, we do a little hack where we change the value
        # of __name__ so log messages produced by this module won't have the
        # useless name "__main__", we need to revert it temporarily to avoid
        # an IPython.embed() warning
        orig_name = __name__
        __name__ = '__main__'
        IPython.embed(display_banner=False)
        __name__ = orig_name

def slice_trace(snapshot_dir, bb_seq):
    """Slices a list of basic block addresses to start at the point the snapshot was
    taken.

    Keyword Arguments:
    snapshot_dir -- Path to the snapshot directory.
    bb_seq -- List of basic block addresses.

    Returns:
    Sliced bb_seq or None if there was an error.
    """
    parts = os.path.basename(snapshot_dir).split('-')
    api_addr, api_seq = (int(parts[0], 16), int(parts[1], 10))
    slice_idx = None
    for idx, addr in enumerate(bb_seq):
        if addr == api_addr:
            api_seq -= 1
        if api_seq < 0:
            slice_idx = idx
            break
    if slice_idx is None:
        return None

    return bb_seq[slice_idx:]

def symbolize_api(state, prototype, parent_addr=None):
    """Symbolizes the arguments in a state entering an API based on the provided
    prototype.

    Prototypes are lists with the following structure:

    [{'value_type': VALUE_TYPE, 'value_data': VALUE_DATA, 'value_size': VALUE_SIZE,
      'offset': OFFSET, 'offset_type': OFFSET_TYPE}, ...]

    Possible values include:
        VALUE_TYPE:
            'Ptr_Code' -- A pointer to some code.
            'Ptr_Data' -- A pointer to some data.
            'Int'      -- An integer.
            'Float'    -- A float.
            'Struct'   -- A pointer to a structure, see VALUE_DATA for details.
        VALUE_DATA:
            For all VALUE_TYPE except Struct, this field is None. When VALUE_TYPE
            is Struct, VALUE_DATA contains a prototype (prototypes are recursive),
            or None if for some reason the definition of this Struct is unknown.
            In the latter case, it will be left untouched to avoid accidentally
            symbolizing any code pointers it may contain.
        VALUE_SIZE:
            When VALUE_TYPE is 'Int' or 'Float', size of the value in bytes. When VALUE_TYPE
            is 'Ptr_Data', size of the buffer it points to. If VALUE_SIZE is None when
            VALUE_TYPE is 'Ptr_Data', buffer is a standalone of arbitrary size.
        OFFSET:
            The integer offset where VALUE_TYPE is located.
        OFFSET_TYPE:
            'Register' -- OFFSET is a VEX register offset.
            'Memory'   -- OFFSET is an absolute virtual memory address.
            'RVA'      -- OFFSET is a virtual address offset relative to the parent.
                          (only used when parent's VALUE_TYPE is Struct)

    OFFSET and OFFSET_TYPE are required, so a parser reading generic prototypes (such
    as in C/C++ headers) must apply the appropriate calling convention to yield a valid
    prototype in the above format. In short, these prototypes are architecture-specific.

    Keyword Arguments:
    state -- The state to symbolize.
    prototype -- The prototype list (defined above).

    Returns:
    None, state is modified directly.
    """
    for arg in prototype:
        # helper lambdas for loading and storing arguments based on offset type
        if arg['offset_type'] == 'Register':
            arg_load = lambda : state.registers.load(arg['offset'])
            arg_store = lambda data: state.registers.store(arg['offset'], data)
        elif arg['offset_type'] == 'Memory':
            arg_load = lambda : state.memory.load(arg['offset'], size=state.arch.bits // 8,
                                                  endness=state.arch.memory_endness)
            arg_store = lambda data: state.memory.store(arg['offset'], data)
        elif arg['offset_type'] == 'RVA':
            if parent_addr is None:
                log.error("Prototype contains a RVA, but has no parent")
                continue
            arg_load = lambda : state.memory.load(arg['offset'] + parent_addr,
                                                  size=state.arch.bits // 8,
                                                  endness=state.arch.memory_endness)
            arg_store = lambda data: state.memory.store(arg['offset'] + parent_addr, data)
        else:
            log.error("Unknown offset type: %s" % arg['offset_type'])
            continue

        if arg['value_type'] == 'Ptr_Code':
            # we have to assume code pointers start uncorrupted, leave them alone
            pass

        elif arg['value_type'] == 'Ptr_Data':
            if arg['value_size'] is None:
                # standalone arbitrary sized buffer, redirect to a new symbolic one
                sym_size = 4096
                sym_buf = state.project.loader.extern_object.allocate(sym_size)
                sym_data = state.solver.BVS('api_arg_buf', sym_size * 8)
            else:
                # fixed size, overwrite existing buffer
                sym_buf = arg_load()
                sym_data = state.solver.BVS('api_arg_buf', arg['value_size'] * 8)

            # insert symbolic data
            state.memory.store(sym_buf, sym_data)
            # update arg pointer
            arg_store(sym_buf)

        elif arg['value_type'] in ['Int', 'Float']:
            # make integers unconstrained
            new_sym = state.solver.BVS('api_arg_int', arg['value_size'] * 8)
            arg_store(new_sym)

        elif arg['value_type'] == 'Struct':
            if not arg['value_data'] is None:
                # recurse into the structure
                symbolize_api(state, arg['value_data'], parent_addr=arg_load())

        else:
            log.error("Unknown prototype value type: %s" % arg['value_type'])

def validate_prototype(prototype):
    """Ensure prototype loaded by lookup_prototype is valid.

    Keyword Arguments:
    prototype -- The prototype.

    Returns:
    True if valid, otherwise False.
    """
    for arg in prototype:
        if not 'offset_type' in arg:
            log.error("Offset type missing in: %s" % str(arg))
            return False

        if not arg['offset_type'] in ['Register', 'Memory', 'RVA']:
            log.error("Invalid offset type: %s" % str(arg['offset_type']))
            return False

        if not 'offset' in arg:
            log.error("Offset missing in: %s" % str(arg))
            return False

        if not isinstance(arg['offset'], int):
            log.error("Offset isn't an integer: %s" % str(arg))
            return False

        for field in ['value_type', 'value_data']:
            if not field in arg:
                log.error("Missing required field: %s" % field)
                return False

        if arg['value_type'] == 'Struct' and not arg['value_data'] is None:
            if not isinstance(arg['value_data'], list):
                log.error("Prototype contains value_data of invalid type: "
                          "%s" % type(arg['value_data']))
                return False
            if not validate_prototype(arg['value_data']):
                return False

    return True

def lookup_prototype(symbol, state):
    """Given a symbol, checks the prototype directory for a corresponding JSON
    and loads it.

    Keyword Arguments:
    symbol -- The symbol name to lookup.
    state -- A state entering the API the prototype pertains to.

    Returns:
    A prototype (see symbolize_api for format details) or None if no match is
    found.
    """
    try:
        proto_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                 "plugins/prototypes/%s.json" % symbol)
        log.debug("Checking for prototype: %s" % proto_dir)

        if not os.path.isfile(proto_dir):
            return None

        with open(proto_dir, 'r') as ifile:
            prototype = json.loads(ifile.read())
    except Exception as ex:
        log.error("Exception while trying to parse %s: %s" % proto_dir, str(ex))
        return None

    # Loaded prototype is generic, so args are in the correct order, but not mapped
    # to a calling convention (non-RVA offset fields are undefined). Fill in this
    # missing data now for the particular state. We only need to consider the outer
    # layer (API arguments), value_data values (Struct) should already have RVAs.
    is_float = list()
    arg_sizes = list()
    for arg in prototype:
        if arg['value_type'] in ['Int', 'Float']:
            arg_sizes.append(arg['value_size'])
        else:
            arg_sizes.append(state.arch.bits // 8)
        is_float.append(arg['value_type'] == 'Float')

    stack = state.solver.eval(state.registers.load(state.arch.sp_offset))

    for arg, loc in zip(prototype, state.project.factory.cc().arg_locs(is_float, arg_sizes)):
        if isinstance(loc, SimRegArg):
            arg['offset_type'] = 'Register'
            arg['offset'] = state.arch.registers[loc.reg_name][0]
        elif isinstance(loc, SimStackArg):
            arg['offset_type'] = 'Memory'
            arg['offset'] = stack + loc.stack_offset

    if validate_prototype(prototype):
        return prototype

    return None

def main():
    """The main method."""
    options, args = parse_args()
    if not options or not args:
        return

    set_log_levels(options)

    log.info("[polyu] options: %s" % options)  # polyu
    log.info("[polyu] args: %s" % args)  # polyu

    trace_dir = args[0]
    input_trace_candidates = ['trace']
    input_trace = None
    for can in input_trace_candidates:
        can_path = os.path.join(trace_dir, can)
        if os.path.isfile(can_path):
            log.debug("Picking %s as input trace" % can_path)
            input_trace = can_path
            break
    if input_trace is None:
        log.error("Trace directory does not appear to contain a valid trace")
        return

    if not options.api_snapshot is None:
        # user wants to load an API snapshot
        snapshot_dir = os.path.join(trace_dir, 'api', options.api_snapshot)
        if not os.path.isdir(snapshot_dir):
            log.error("Cannot find %s" % snapshot_dir)
            return
    else:
        # use the default entry point snapshot
        snapshot_dir = trace_dir

    # load some data
    with open(os.path.join(snapshot_dir, 'misc.json'), 'r') as ifile:
        misc = json.load(ifile)
    with open(os.path.join(snapshot_dir, 'regs.txt'), 'r') as ifile:
        regs = {}
        for line in ifile.readlines():
            line = line.strip().split("]")[1].strip()
            name = line.split("=")[0].strip()
            value = int(line.split("=")[1].strip(), 0)
            regs[name] = value

    # get all tasks contained in the trace
    trace_pids = nprofiler.get_pid_list(input_trace)

    # pick PID and get disassembly
    if len(trace_pids) == 0:
        log.error("Cannot find PIDs for tasks in trace")
        return
    elif options.pid and options.pid in trace_pids:
        log.info("Disassembling ETM trace for PID: %d" % options.pid)
        bb_seq = nprofiler.disasm_pt_file(input_trace, pids=options.pid)
    elif not options.pid:
        if len(trace_pids) == 1:
            target_pid = trace_pids[0]
            log.info("Disassembling ETM trace for PID: %d" % target_pid)
            bb_seq = nprofiler.disasm_pt_file(input_trace, pids=target_pid)
        else:
            # try to intelligently pick the right PID by taking the first one that
            # has the starting/snapshot address in its trace
            log.info("No PID specified and trace contains several, trying to pick best option...")
            for pid in trace_pids:
                log.info("Disassembling ETM trace for PID: %d" % pid)
                bb_seq = nprofiler.disasm_pt_file(input_trace, pids=pid)
                ## if regs['pc'] in bb_seq:
                    ## log.warn("No task specified with --pid, picking %d to analyze from: "
                             ## "%s" % (pid, str(trace_pids)))
    else:
        log.error("Cannot find specified PID %d in trace: %s" % (options.pid, str(trace_pids)))
        return

    # log.info("[polyu] bb_seq: %s" % bb_seq)  # polyu

    if not options.api_snapshot is None:
        # PT recorded the full trace, but user wants to start at an API snapshot, so
        # we have to slice the trace
        bb_seq = slice_trace(snapshot_dir, bb_seq)
        if bb_seq is None:
            log.error("Failed to find point in trace where API snapshot was taken")
            return

    bin_dir = os.path.join(snapshot_dir, 'bin/')
    # bin_temp = tempfile.mkdtemp(prefix='analysis-')
    rootdir = "/home/zhouhao/AOSP/ARCUS/tools/angr/tmp"
    tmpname = "analysis-" + str(int(time.time()))
    tmpdir = os.path.join(rootdir, tmpname)
    os.mkdir(tmpdir)
    bin_temp = tmpdir
    lib_opts = dict()
    lib_files = list()
    main_opts = dict()
    main_fp = None
    for item in os.listdir(bin_dir):
        fullfp = os.path.realpath(os.path.join(bin_dir, item))
        base_va, name = item.split('-', 1)
        base_va = int(base_va, 16)
        if item == misc['main']:
            main_opts = {'base_addr': base_va}
            main_fp = fullfp
        elif '.so' in name:
            lib_opts[name] = {'base_addr': base_va}
            lib_files.append(name)
        else:
            # CLE only loads programs and libraries
            log.debug("Skipping %s in CLE initial load libraries" % name)
        # We prefixed the base virtual address in the names of the binaries, which will
        # mess up the loader. To account for this, we create a new directory with symlinks
        # given the original names that point to the binaries and then force the loader to
        # only load from this directory.
        try:
            os.link(fullfp, os.path.join(bin_temp, name))
        except PermissionError:
            log.error("Failed to symlink %s, permission denied" % fullfp)
            shutil.rmtree(bin_temp)
            return

    log.info("[polyu] main_fp: %s" % main_fp)  # polyu
    log.info("[polyu] main_opts: %s" % main_opts)  # polyu
    log.info("[polyu] lib_files: %s" % lib_files)  # polyu
    log.info("[polyu] lib_opts: %s" % lib_opts)  # polyu
    proj = angr.Project(main_fp, main_opts=main_opts, force_load_libs=lib_files, lib_opts=lib_opts,
            use_sim_procedures=True, except_missing_libs=False, ld_path=[bin_temp], use_system_libs=False)

    # apply any relevant custom hooks/simprocedures
    hooks.apply_hooks(proj)

    # initialize the starting state, exploration technique and simulation manager
    tech = angretm.Tracer(bb_seq, start_address=regs['pc'])
    init_state = parse_entry_state_json(proj, trace_dir, snapshot_dir, False,
                                                  options.override_max_argv)
    simgr = proj.factory.simgr(init_state)

    try:
        simgr.use_technique(tech)
    except angr.errors.AngrTracerError as ex:
        log.error("Failed to setup tracer: %s" % str(ex))
        shutil.rmtree(bin_temp)
        return

    if options.disable_detectors:
        plugins.detectors.loaded = dict()

    if not options.api_snapshot is None:
        # log name of API
        api_succ = init_state.step().successors[0]
        succ_obj = proj.loader.find_object_containing(api_succ.addr)
        api_sym_obj = proj.loader.find_symbol(api_succ.addr, fuzzy=True)
        if api_sym_obj is None:
            api_sym_name = 'unknown'
        else:
            api_sym_name = api_sym_obj.name
        log.info("API Name: %s" % api_sym_name)

        # selectively symbolize state
        func_prototype = lookup_prototype(api_sym_name, init_state)
        if func_prototype is None:
            if options.api_inference:
                log.warning("No predefined prototype for %s, inferring it" % api_sym_name)
                func_prototype = taint.infer_function_prototype(init_state, bb_seq)
            else:
                log.error("No predefined prototype for %s, inferring is disabled by default"
                          " because it can result in false positive reports, if you *really*"
                          " want it, rerun with --api-inference option" % api_sym_name)
                shutil.rmtree(bin_temp)
                return

        log.debug("API Prototype:\n%s" % json.dumps(func_prototype, indent=2, sort_keys=True))
        symbolize_api(init_state, func_prototype)

        # API may be hooked, move PC 1 step forward to avoid this
        bb_seq.pop(0)
        init_state.registers.store(init_state.arch.ip_offset, bb_seq[0])

    # optimization on consumed memory?
    min_memory = int(psutil.virtual_memory().total * 0.05)
    crit_memory = int(psutil.virtual_memory().total * 0.01)
    mem_mgr = agc.AnalysisGC(simgr)

    ###################################################
    ### PHASE 1: Follow the trace and look for bugs ###
    ###################################################

    # Let's pray this weapon surpasses Metal Gear...
    log.info("Starting symbolic analysis")
    analysis_start_time = datetime.now()
    bug_stashes = [module.stash_name for module in list(plugins.detectors.loaded.values())]
    log.info("[polyu] bug_stashes: %s" % str(bug_stashes))  # polyu
    for detector in list(plugins.detectors.loaded.values()):
        detector.active = True
    try:
        for name in bug_stashes:
            simgr.populate(name, [])
        maybe_unsat = False

        mem_mgr.enable()
        while len(simgr.stashes['active']) > 0:
            # log.info("[polyu] addr-0: %#x" % simgr.one_active.addr)  # polyu
            log.info("[polyu] addr-0: %s" % str(simgr.active))  # polyu
            simgr.step()
            # log.info("[polyu] addr-1: %#x" % simgr.one_active.addr)  # polyu
            log.info("[polyu] addr-1: %s" % str(simgr.active))  # polyu
            if len(simgr.stashes['active']) > 0:
                active_state = simgr.stashes['active'][0]

                # check state and CLI arguments for if we should IPython.embed for debugging
                debug_embedding_hook(active_state, options)

                if not maybe_unsat and not active_state.solver.satisfiable():
                    log.warn("Current active state may no longer be satisfiable")
                    maybe_unsat = True
                    if options.stop_unsat:
                        log.error("Active state is unsatisfiable, restoring prior state and halting analysis")
                        # revert back to previous state so we end analysis on something satisfiable
                        pred_state = get_predecessor(tech, -1)
                        assert pred_state.solver.satisfiable()
                        simgr.stashes['active'][0] = pred_state
                        raise angr.errors.AngrTracerError("Active state is unsat")
                    else:
                        log.warn("Under constraining state to continue analysis")

                # if unsat, under constrain (this is only reachable if options.stop_unsat == False)
                if not active_state.solver.satisfiable():
                    log.debug("Under constraining")
                    pred_state = get_predecessor(tech, -1)
                    assert pred_state.solver.satisfiable()
                    # remove constraint tracking and replace current state
                    pred_state.options.remove(sim_options.TRACK_CONSTRAINTS)
                    simgr.stashes['active'][0] = pred_state
                    # step to same address, re-enable tracking
                    simgr.step()
                    simgr.stashes['active'][0].options.add(sim_options.TRACK_CONSTRAINTS)
                    assert simgr.stashes['active'][0].satisfiable()

            check_for_vulns(simgr, proj)

            if psutil.virtual_memory().available <= min_memory:
                mem_mgr.reap_predecessors()
            if psutil.virtual_memory().available <= crit_memory:
                raise CriticalMemoryException('Memory critically low')

            analysis_duration = (datetime.now() - analysis_start_time).total_seconds()

    except KeyboardInterrupt:
        log.warning("Received interrupt, cleaning up...")
    except (CriticalMemoryException, MemoryError):
        log.error("Memory critically low, halting analysis")
    except AssertionError:
        log.error("Failed assertion: %s" % format_exc())
    except angr.errors.AngrTracerError as ex:
        log.error("Angr stopped early: %s" % str(ex))

    mem_mgr.disable()

    try:
        # one last check for vulns
        check_for_vulns(simgr, proj)

        if len(simgr.active) > 0:
            try:
                addr_desc = proj.loader.describe_addr(simgr.active[0].addr)
                log.error("Stopped here: %#x %s" % (simgr.active[0].addr, addr_desc))
            except angr.errors.SimValueError:
                log.error("Stopped here: (symbolic)")
    except KeyboardInterrupt:
        log.warning("Received interrupt, cleaning up...")

    # update reports
    log.info("Updating reports with root cause analysis")
    try:
        reports = analyze(simgr, bb_seq)
    except KeyboardInterrupt:
        log.warning("Received interrupt, cleaning up...")

    exit()

    ################################
    ### PHASE 2: Final Reporting ###
    ################################

    log.info("** Analysis complete, final results **")

    # generic stashes with no associated plugin
    stash_names = {'active':    'Active',
                   'missed':    'Missed',
                   'traced':    'Traced',
                   'crashed':   'Crashed',
                   'deadended': 'Dead End',
                  }

    # stashes with an associated detector plugin
    for detector in list(plugins.detectors.loaded.values()):
        stash_names[detector.stash_name] = detector.pretty_name

    # log info on found bugs
    summarize_stashes(simgr.stashes, stash_names, reports, proj.loader, options.stack_depth)

    # save examples and/or reports, if requested
    if not options.save_reports is None:
        save_reports(reports, options.save_reports)
    if not options.save_examples is None:
        if psutil.virtual_memory().available <= crit_memory:
            log.error("Memory critically low, cannot save examples")
        else:
            save_examples(simgr, init_env['argv'], simgr.stashes.keys(),
                          options.save_examples, trace_dir)

    # cleanup
    shutil.rmtree(bin_temp)

    # report any plugins that experienced bugs during analysis
    # for future debugging
    if len(buggy_plugins) > 0:
        log.warning("The following plugins experienced bugs, see prior logs for "
                    "detailed stack traces: %s" % ', '.join(list(buggy_plugins)))


'''
if __name__ == '__main__':
    signal.signal(signal.SIGTERM, sigterm_handler)
    __name__ = 'analysis'
    hooked_idx = False
    buggy_plugins = set()
    log = logging.getLogger(__name__)
    main()
'''

# main function for unit test (polyu)
import time
if __name__ == '__main__':
    # create tmpdir
    rootdir = "/home/zhouhao/AOSP/ARCUS/tools/angr/tmp"
    if os.path.exists(rootdir) and os.path.isdir(rootdir):
        shutil.rmtree(rootdir)
    os.mkdir(rootdir)
    tmpname = "analysis-unittest" + str(int(time.time()))
    tmpdir = os.path.join(rootdir, tmpname)
    os.mkdir(tmpdir)

    # configure sys.argv
    sys.argv.append("--save-reports")
    sys.argv.append(tmpdir)
    # sys.argv.append("/home/zhouhao/AOSP/ARCUS/tools/angr/test/test-data/traces/etm-uaf-01-ben")
    sys.argv.append("/home/zhouhao/AOSP/ARCUS/tools/angr/test/test-data/traces/etm-df-01-ben")

    signal.signal(signal.SIGTERM, sigterm_handler)
    __name__ = 'analysis'
    hooked_idx = False
    buggy_plugins = set()
    log = logging.getLogger(__name__)
    main()
