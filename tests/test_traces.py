import unittest
import subprocess
import logging
import os.path
import re

from bintrace import Trace, ImageMapEvent, InsnEvent, MemoryEvent
from bintrace.debugger import TraceDebugger, Breakpoint, BreakpointType
from bintrace.debugger_angr import AngrTraceDebugger

logging.basicConfig(level=logging.DEBUG)
_l = logging.getLogger(__name__)


def get_symbols(bin, base=0):
    m = subprocess.check_output(f'nm {bin}'.split(), encoding='utf-8')
    return {name: (base + int(addr, 16)) for addr, name in re.findall(r'(\w+) \w (.*)', m)}


class TraceTest(unittest.TestCase):
    """
    Run tests for Trace and TraceDebugger.
    """

    @classmethod
    def setUpClass(cls):
        _l.info('Compiling test binary...')
        subprocess.run('gcc -o simple_global simple_global.c'.split(), check=True)

        _l.info('Collecting trace...')
        subprocess.run('seq 100 110 | bintrace-qemu ./simple_global > /dev/null', shell=True)

        cls.tm = Trace()
        cls.tm.load_trace('simple_global.trace')
        cls.syms = get_symbols('simple_global', next(cls.tm.filter_image_map()).Base())

    #
    # Test Trace Manager
    #

    def test_filter_exec_addr(self):
        self.assertEqual(len(list(self.tm.filter_exec_addr(self.syms['loop_bottom']))), 10)

    def test_filter_memory(self):
        addr = self.syms['global_value']
        values = []
        state = None
        for ev in self.tm.filter_memory(addr, 4, store=True):
            next_exec_ev = self.tm.get_next_exec_event(ev)
            state = self.tm.replay(state, next_exec_ev)
            values.append(state.get_int(addr, 4))
        self.assertEqual(values, list(range(100, 110)))

    #
    # Test Trace Debugger
    #

    def test_breakpoint(self):
        d = TraceDebugger(self.tm)
        d.breakpoints.add(Breakpoint(BreakpointType.Execute, self.syms['loop_bottom']))
        values = []
        d.continue_forward()
        while not self.tm.is_at_end(d.state):
            values.append(d.state.get_int(self.syms["global_value"], 4))
            d.continue_forward()
        self.assertEqual(values, list(range(100, 110)))

    def test_breakpoint_reverse(self):
        d = TraceDebugger(self.tm)
        d.continue_forward()
        d.breakpoints.add(Breakpoint(BreakpointType.Execute, self.syms['loop_bottom']))
        values = []
        d.continue_backward()
        while not self.tm.is_at_start(d.state):
            values.append(d.state.get_int(self.syms["global_value"], 4))
            d.continue_backward()
        self.assertEqual(values, list(range(109,99,-1)))

    def test_watchpoint_write(self):
        d = TraceDebugger(self.tm)
        d.breakpoints.add(Breakpoint(BreakpointType.Write, self.syms['global_value'], 4))
        values = []
        d.continue_forward()
        while not self.tm.is_at_end(d.state):
            d.continue_forward()
            values.append(d.state.get_int(self.syms["global_value"], 4))
        self.assertEqual(values, list(range(100, 110)))

    def test_watchpoint_reverse(self):
        d = TraceDebugger(self.tm)
        d.continue_forward()
        d.breakpoints.add(Breakpoint(BreakpointType.Write, self.syms['global_value'], 4))
        d.continue_backward()
        values = []
        while not self.tm.is_at_start(d.state):
            d.continue_forward()
            values.append(d.state.get_int(self.syms["global_value"], 4))
            d.continue_backward()
            d.continue_backward()
        self.assertEqual(values, list(range(109,99,-1)))

    def test_forking(self):
        prog = 'forking_prog'
        prog_src = f'{prog}.c'
        subprocess.run(f'gcc -o {prog} {prog_src}'.split(), check=True)
        subprocess.run(f'bintrace-qemu ./{prog} > /dev/null', shell=True)

        tm = Trace()
        tm.load_trace(f'{prog}.trace')
        syms = get_symbols(f'{prog}', next(tm.filter_image_map()).Base())
        pids = [e.Value() for e in tm.filter_memory(syms['child_pid'], 4, store=True)]
        assert len(pids) == 5
        for i, pid in enumerate(pids):
            tm = Trace()
            tm.load_trace(f'{prog}.trace.{pid}.trace')
            self.assertEqual(len(list(tm.filter_exec_addr(syms['child_path']))), 1)
            child_pid = [e.Value() for e in tm.filter_memory(syms['child_pid'], 4, store=True)]
            assert len(child_pid) == (i + 1)
            assert child_pid[-1] == pid

    def test_threads(self):
        prog = 'threaded_prog'
        prog_src = f'{prog}.c'
        subprocess.run(f'gcc -o {prog} -pthread {prog_src}'.split(), check=True)
        subprocess.run(f'bintrace-qemu ./{prog} > /dev/null', shell=True)

        tm = Trace()
        tm.load_trace(f'{prog}.trace')
        syms = get_symbols(f'{prog}', next(tm.filter_image_map()).Base())
        thread_count = 5
        bp = {
            Breakpoint(BreakpointType.Execute, syms['create_thread']),
            Breakpoint(BreakpointType.Execute, syms['thread_routine']),
            Breakpoint(BreakpointType.Write, syms['thread_mark'], thread_count*4),
            Breakpoint(BreakpointType.Execute, syms['thread_exit']),
            Breakpoint(BreakpointType.Execute, syms['wait_for_thread']),
        }

        def is_stopped_at(d, sym_name):
            return isinstance(d.state.event, InsnEvent) and d.state.event.Addr() == syms[sym_name]

        # Trace initial thread path
        d = TraceDebugger(tm, vcpu=0)
        d.breakpoints = bp
        for _ in range(thread_count):
            d.continue_forward()
            assert is_stopped_at(d, 'create_thread')
        for _ in range(thread_count):
            d.continue_forward()
            assert is_stopped_at(d, 'wait_for_thread')
        d.continue_forward()
        assert tm.is_at_end(d.state)

        # Trace each created thread path
        for thread in range(thread_count):
            d = TraceDebugger(tm, vcpu=(thread + 1))
            d.breakpoints = bp

            d.continue_forward()
            assert is_stopped_at(d, 'thread_routine')

            d.continue_forward()
            mark_addr = syms['thread_mark'] + thread*4
            assert isinstance(d.state.event, MemoryEvent) and d.state.event.Addr() == mark_addr
            d.step_forward()
            thread_mark = d.state.get_int(mark_addr, 4)
            assert thread_mark == (100 + thread)

            d.continue_forward()
            assert is_stopped_at(d, 'thread_exit')

            d.continue_forward()
            assert tm.is_at_end(d.state)

    #
    # Test angr Trace Debugger
    #

    def test_angr_libc_call_recovery(self):
        d = AngrTraceDebugger(self.tm)
        expected_addr = None
        for sev in self.tm.filter_memory(self.syms['global_value'], 4, store=True):
            # Step back through trace to last instruction executed within text segment of target binary
            mo = d.project.loader.main_object.sections_map['.text']
            e = None
            def iter_backwards(start):
                ev = start
                while ev:
                    yield ev
                    ev = self.tm.get_prev_event(ev)
            # FIXME: Provide native filtered version for address in range
            for e in iter_backwards(sev):
                if isinstance(e, InsnEvent) and mo.min_addr <= e.Addr() <= mo.max_addr:
                    break
            self.assertIsNotNone(e)

            # Check address (it should be written only from one call to scanf)
            if expected_addr is None:
                expected_addr = e.Addr()
            else:
                self.assertEqual(expected_addr, e.Addr())

        # Check block disassembly
        d.state = self.tm.replay(d.state, e)
        disas = d.simstate.block().disassembly.insns[0]
        self.assertEqual(disas.mnemonic, 'call')

        # Check that stepping once correctly updates stack
        d.step_forward()
        ss = d.simstate
        self.assertEqual(ss.solver.eval(ss.stack_read(0, 8)), disas.address + disas.size)

    def test_angr_breakpoint_and_load_global_value_from_simstate(self):
        d = AngrTraceDebugger(self.tm)
        values = []
        d.breakpoints.add(Breakpoint(BreakpointType.Execute, self.syms['loop_bottom']))
        d.continue_forward()
        while not self.tm.is_at_end(d.state):
            ss = d.simstate
            values.append(ss.solver.eval(ss.memory.load(self.syms["global_value"], 4, endness='Iend_LE')))
            d.continue_forward()
        self.assertEqual(values, list(range(100, 110)))


if __name__ == '__main__':
  unittest.main()
