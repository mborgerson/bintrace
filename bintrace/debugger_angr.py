from collections import defaultdict
from typing import Optional
import logging
import os.path

import pyvex
import angr
from angr.engines import HeavyVEXMixin, SimInspectMixin
from angr.engines.engine import SuccessorsMixin
from angr.engines.procedure import ProcedureMixin

from .tracemgr import TraceManager, InsnEvent, MemoryEvent, SyscallRetEvent
from .debugger import TraceDebugger

_l = logging.getLogger(name=__name__)


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


def create_angr_project_from_trace(tm: TraceManager):
    _l.info('Creating project from mapped images in trace')
    mappings = list(tm.filter_image_map())
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

    ld_opts = {'main_opts': {'base_addr': main_binary.Base()},
               'auto_load_libs': False,
               'force_load_libs': [os.path.realpath(name) for name in lib_map],
               'lib_opts': {os.path.realpath(name): {'base_addr': lib.Base()} for name, lib in lib_map.items()},
               }

    return angr.Project(main_binary.Name().decode('utf-8'), load_options=ld_opts)


class AngrTraceDebugger(TraceDebugger):
    """
    Debugger-like interface for trace playback that can create angr states.
    """

    def __init__(self, tm: TraceManager, project: Optional[angr.Project] = None):
        super().__init__(tm)

        if project is None:
            project = create_angr_project_from_trace(tm)

        self.project: angr.Project = project

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
        if self.state.event is None or self._tm.is_at_start(self.state):
            _l.error('Not at a valid position to create simstate')
            return None

        bb = self._tm.get_prev_bb_event(self.state.event)
        _l.info('Rewind to last BB event %s', bb)
        state = self.state.snapshot()
        state = self._tm.replay(state, bb)

        load_events = {}
        syscall_events = {}
        last_insn = None

        def range_events(start, until):
            ev = start
            while ev is not None and ev.handle < until.handle:
                yield ev
                ev = self._tm.get_next_event(ev)

        for event in range_events(bb, self.state.event):
            _l.info(event)
            if isinstance(event, InsnEvent):
                last_insn = event.Addr()
                load_events[last_insn] = []
            elif isinstance(event, MemoryEvent) and not event.IsStore():
                load_events[last_insn].append(event)
            elif isinstance(event, SyscallRetEvent):
                syscall_events[last_insn] = event

        # Slow memory store to state
        # FIXME: replace with faster, no-copy version...
        simstate = self.project.factory.blank_state()
        for addr, size in state.get_contiguous_ranges():
            simstate.memory.store(addr, state.get_bytes(addr, size))

        # FIXME: Some registers are not modeled here (e.g. FS), so execution may be incorrect
        #        Need to model rflags
        # FIXME: Should determine register list from arch structure (it maps GDB's listing)
        dregs = ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8',
                 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'pc', 'eflags')
        for i, name in enumerate(dregs):
            setattr(simstate.regs, name, bb.Regs(i))

        simstate.regs.cc_op = 0 # Copy
        simstate.regs.cc_dep1 = bb.Regs(17)
        simstate.regs.cc_dep2 = 0
        simstate.regs.cc_ndep = 0

        # Gather all loads executed by each instruction, and write them just in
        # time to state memory before executing the instruction.
        def before_insn_exec(state):
            _l.info('Executing @ %s', state.regs.pc)
            for event in load_events[state.solver.eval(state.regs.pc)]:
                _l.info('   -> %s', event)
                state.memory.store(event.Addr(), event.Value(), size=(1<<event.Size()))

        simstate.inspect.b('instruction', when=angr.BP_BEFORE, action=before_insn_exec)

        def update_syscall_state(state):
            # XXX: Should use BP_AFTER with original IP
            pc = state.solver.eval(state.regs.pc)
            if pc in syscall_events:
                state.regs.rax = syscall_events[pc].ret
        simstate.inspect.b('instruction', when=angr.BP_BEFORE, action=update_syscall_state)

        insns = [e for e in range_events(bb, self.state.event) if isinstance(e, InsnEvent)]
        if len(insns) == 0:
            return simstate

        _l.info('Block Instructions:')
        insn_data = b''
        for insn in insns:
            _l.info(' - %s', insn)
            insn_data += bytes(insn.Bytes(i) for i in range(insn.BytesLength()))

        _l.info('Lifting Block:')
        irsb = pyvex.IRSB(insn_data, bb.Addr(), self.project.arch)
        _l.info('%s', irsb)

        # XXX: We are executing w/ Vex engine, but it might as well be Unicorn.
        #      It's typically only a handful of instructions.
        _l.info('Executing at %s, up to %s', simstate.regs.pc, self.state.event)
        sim_successors = InspectEngine(None).process(simstate, irsb=irsb)
        if len(sim_successors.successors) != 1:
            _l.warning('!!! Unexpected number of successors: %d (%d total)',
                       len(sim_successors.successors), len(sim_successors.all_successors))
            for s in sim_successors.all_successors:
                _l.info('--> %s %s', s, '(unsat)' if s in sim_successors.unsat_successors else '')

        return sim_successors.all_successors[0]
