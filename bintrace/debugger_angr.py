from collections import defaultdict
from typing import Optional
from bisect import bisect_left
import logging
import os.path

import pyvex
import angr
import claripy
from angr.engines import HeavyVEXMixin, SimInspectMixin
from angr.engines.engine import SuccessorsMixin
from angr.engines.procedure import ProcedureMixin
from angr.storage.memory_mixins import FastMemory

from .tracemgr import Trace, InsnEvent, MemoryEvent, SyscallRetEvent
from .debugger import TraceDebugger


_l = logging.getLogger(name=__name__)


# pylint:disable=abstract-method
class BintraceMemory(FastMemory):
    """
    Memory plugin providing data from recovered trace state.
    """

    def __init__(self, bintrace_state=None, **kwargs):
        super().__init__(**kwargs)
        self._trace = bintrace_state
        self._ranges = self._trace.get_contiguous_ranges()

    def copy(self, memo):
        o = super().copy(memo)
        o._trace = self._trace
        o._ranges = self._ranges
        return o

    def _fill(self, addr, size, vargs, kwargs):
        """
        Fill from first overlapping range within trace memory state, if available.
        """
        start_idx = max(0, bisect_left(self._ranges, (addr,)) - 1)

        for tr_addr, tr_size in self._ranges[start_idx:]:
            if tr_addr >= (addr + size):
                break
            if addr >= (tr_addr + tr_size):
                continue
            if tr_addr > addr:
                return super()._default_value(addr, tr_addr - addr, *vargs, **kwargs)
            bytes_available = tr_size - (addr - tr_addr)
            return claripy.BVV(self._trace.get_bytes(addr, min(bytes_available, size)))

        return super()._default_value(addr, size, *vargs, **kwargs)

    def _default_value(self, addr, size, *vargs, **kwargs):
        """
        Iteratively fill from contiguous blocks of trace state memory to satisfy the fill request. Use next default
        filler for gaps.
        """
        d, num_bytes_filled = [], 0
        while num_bytes_filled < size:
            v = self._fill(addr + num_bytes_filled, size - num_bytes_filled, vargs, kwargs)
            num_bytes_filled += v.size() // 8
            d.append(v)
        bvv = claripy.Concat(*d) if len(d) > 1 else d[0]
        return bvv if kwargs.get('endness', 'Iend_BE') == 'Iend_BE' else bvv.reversed


# FIXME: Tests for syscall. Needs engine fixes for proper support.
# pylint:disable=abstract-method,arguments-differ
class NoSyscallEffectMixin(SuccessorsMixin, ProcedureMixin):
    """
    Helper for block state recovery.
    """

    def process_successors(self, successors, **kwargs):
        state = self.state
        # we have at this point entered the next step so we need to check the previous jumpkind
        if (not state.history
                or not state.history.parent
                or not state.history.parent.jumpkind
                or not state.history.parent.jumpkind.startswith('Ijk_Sys')):
            super().process_successors(successors, **kwargs)
        successors.processed = True


class InspectEngine(NoSyscallEffectMixin, SimInspectMixin, HeavyVEXMixin):
    """
    Helper for block state recovery.
    """


def get_angr_project_load_options_from_trace(tm: Trace):
    mappings = list(tm.filter_image_map())
    if len(mappings) == 0:
        return None

    main_binary = mappings[0]
    libs = mappings[1:] if len(mappings) > 1 else []
    lib_map = defaultdict(list)
    for lib in libs:
        lib_map[lib.Name().decode('utf-8')].append(lib)
    for name in list(lib_map.keys()):
        if name in (main_binary.Name().decode('utf-8'), '/etc/ld.so.cache'):
            lib_map.pop(name)
        elif not os.path.exists(os.path.realpath(name)):
            _l.warning('Could not find binary %s', name)
            lib_map.pop(name)
        else:
            # XXX: We simply take the lowest address as image base. Possible failure.
            lib_map[name] = min(lib_map[name], key=lambda l: l.Base())

    return {
        'thing': main_binary.Name().decode('utf-8'),
        'load_options': {
            'main_opts': {
                'base_addr': main_binary.Base()
            },
            'auto_load_libs': False,
            # 'force_load_libs': [os.path.realpath(name) for name in lib_map],
            # 'lib_opts': {os.path.realpath(name): {'base_addr': lib.Base()} for name, lib in lib_map.items()},
        }
    }


def create_angr_project_from_trace(tm: Trace):
    _l.info('Creating project from mapped images in trace')
    load_opts = get_angr_project_load_options_from_trace(tm)
    return angr.Project(**load_opts)


class AngrTraceDebugger(TraceDebugger):
    """
    Debugger-like interface for trace playback that can create angr states.
    """

    def __init__(self, tm: Trace, project: Optional[angr.Project] = None):
        super().__init__(tm)

        if project is None:
            project = create_angr_project_from_trace(tm)

        self.project: angr.Project = project

        # FIXME: Allow more flexible step ranges
        step_range_min = self.project.loader.main_object.min_addr
        step_range_max = self.project.loader.main_object.max_addr
        for obj in self.project.loader.all_objects:
            if obj.binary.startswith('cle##'):
                continue  # FIXME: Add better check
            step_range_min = min(step_range_min, obj.min_addr)
            step_range_max = max(step_range_max, obj.max_addr)
        self.single_step_range = (step_range_min, step_range_max - step_range_min + 1)

    @property
    def simstate(self) -> angr.SimState:
        """
        Get current simulation state.
        """
        return self._get_simstate()

    def _get_simstate(self) -> Optional[angr.SimState]:
        """
        Load register and memory state from most recent BB event, then execute up to current state address.
        """
        if self.state is None or self.state.event is None or self._tm.is_at_start(self.state):
            _l.error('Not at a valid position to create simstate, returning blank state')
            return self.project.factory.blank_state()

        #
        # Trace events come in an order like:
        # [Block]
        #   [Instruction]
        #      [Load/Store] for the previous instruction
        #      [Syscall] invoked by the previous instruction
        #   [Instruction]
        #   [Instruction]
        # ...
        #
        # Replay from last block event up to, but not including last exec event.

        bb = self._tm.get_prev_bb_event(self.state.event, vcpu=self.vcpu)
        _l.info('Rewind to last BB event %s', bb)
        state = self.state.snapshot()
        state = self._tm.replay(state, bb)

        load_events = {}
        syscall_events = {}

        def range_events(start, until):
            ev = start
            while ev is not None and ev.handle < until.handle:
                yield ev
                ev = self._tm.get_next_event(ev)

        if isinstance(self.state.event, InsnEvent):
            stop_event = self.state.event
        else:
            stop_event = self._tm.get_prev_exec_event(self.state.event, vcpu=self.vcpu)

        last_insn = None
        for event in range_events(bb, stop_event):
            if isinstance(event, InsnEvent) and event.Vcpu() == self.vcpu:
                _l.info(event)
                last_insn = event.Addr()
                load_events[last_insn] = []
            elif isinstance(event, MemoryEvent) and (not event.IsStore()) and event.Vcpu() == self.vcpu:
                _l.info(event)
                load_events[last_insn].append(event)
            elif isinstance(event, SyscallRetEvent) and event.Vcpu() == self.vcpu:
                _l.info(event)
                syscall_events[last_insn] = event

        mem = BintraceMemory(bintrace_state=state, memory_id='mem')
        simstate = angr.SimState(self.project, mode='symbolic', plugins={'memory': mem})

        # FIXME: Some registers are not modeled here (e.g. FS), so execution may be incorrect
        #        Need to model rflags
        # FIXME: Should determine register list from arch structure (it maps GDB's listing)
        if self.project.arch.name == 'AMD64':
            dregs = ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8',
                     'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'pc', 'eflags')
        elif self.project.arch.name == 'X86':
            dregs = ('eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi', 'pc', 'eflags')
        else:
            assert False, 'FIXME: Make register info generic'

        for i, name in enumerate(dregs):
            setattr(simstate.regs, name, bb.Regs(i))

        simstate.regs.cc_op = 0  # Copy
        simstate.regs.cc_dep1 = bb.Regs(len(dregs)-1)
        simstate.regs.cc_dep2 = 0
        simstate.regs.cc_ndep = 0

        insns = [e for e in range_events(bb, stop_event) if (isinstance(e, InsnEvent) and e.Vcpu() == self.vcpu)]
        if len(insns) < 1:
            return simstate

        # Gather all loads executed by each instruction, and write them just in
        # time to state memory before executing the instruction.
        def before_insn_exec(state):
            _l.info('Executing @ %s', state.regs.pc)
            pc = state.solver.eval(state.regs.pc)
            for event in load_events[pc]:
                state.memory.store(event.Addr(), event.Value(), size=(1 << event.Size()),
                                   endness=state.arch.memory_endness)

        bp1 = simstate.inspect.b('instruction', when=angr.BP_BEFORE, action=before_insn_exec)

        def update_syscall_state(state):
            # XXX: Should use BP_AFTER with original IP
            pc = state.solver.eval(state.regs.pc)
            if pc in syscall_events:
                state.regs.rax = syscall_events[pc].Ret()

        bp2 = simstate.inspect.b('instruction', when=angr.BP_BEFORE, action=update_syscall_state)

        _l.info('Block Instructions:')
        insn_data = b''
        for insn in insns:
            _l.info(' - %s', insn)
            insn_data += bytes(insn.Bytes(i) for i in range(insn.BytesLength()))

        _l.info('Lifting Block:')
        irsb = pyvex.IRSB(insn_data, bb.Addr(), self.project.arch, opt_level=0)
        _l.info('%s', irsb)

        # XXX: We are executing w/ Vex engine, but it might as well be Unicorn.
        #      It's typically only a handful of instructions.
        _l.info('Executing at %s, up to %s', simstate.regs.pc, stop_event)
        sim_successors = InspectEngine(None).process(simstate, irsb=irsb)
        if len(sim_successors.successors) != 1:
            _l.warning('!!! Unexpected number of successors: %d (%d total)',
                       len(sim_successors.successors), len(sim_successors.all_successors))
            for s in sim_successors.all_successors:
                _l.info('--> %s %s', s, '(unsat)' if s in sim_successors.unsat_successors else '')

        s = sim_successors.all_successors[0]
        s.inspect.remove_breakpoint('instruction', bp1)
        s.inspect.remove_breakpoint('instruction', bp2)
        return s
