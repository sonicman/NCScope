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

def get_pid_list(source):
    """Get the list of PIDs contained in a trace, in the order they first appear."""
    pids = list()

    fp = open(source, 'r')
    for line in fp.readlines():
        line = line.strip()
        if ("Context ID = " in line) and ("," in line):
            # print(line)
            pid_string = line.split("Context ID = ")[1].split(",")[0]
            pid = int(pid_string, 0)
            if not (pid in pids):
                pids.append(pid)
        else:
            continue
    fp.close()

    return pids


def disasm_pt_file(trace_path, event='block', pids=None):
    """Disassembles a PT trace, returning a list of events.

    By default, block events are yielded. See disasm_events for other possible events.
    For events that contain multiple values (e.g. xpage), the resulting list will contain
    tuples. Values are automatically encoded into sane representations. For example, numbers
    will be ints, not strs.

    By default, events for all PIDs are returned. Passing an int or list of ints as pids will
    filter inclusively.

    Raises PTNotFound if pt cannot be located and DisasmError if something goes wrong.

    Returns a list of event values.
    """

    addrs = list()

    fp = open(trace_path, 'r')
    for line in fp.readlines():
        line = line.strip()
        if ("Instruction address " in line) and ("," in line):
            # print(line)
            addr_string = line.split("Instruction address ")[1].split(",")[0]
            if addr_string.startswith("0xffffff"):
                continue
            if addr_string.startswith("0x0000007f"):
                continue
            # print(addr_string)
            addr = int(addr_string, 0)
            addrs.append(addr)

            # if addr == 0x0000007a1c6c3500:
            if addr == 0x0000007124c73500:
                break
        else:
            continue
    fp.close()

    return addrs