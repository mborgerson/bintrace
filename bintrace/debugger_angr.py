from typing import Optional
import pyvex
import logging
import angr
import os.path
from angr.engines import HeavyVEXMixin, SimInspectMixin
from angr.engines.engine import SuccessorsMixin
from angr.engines.procedure import ProcedureMixin

from .tracemgr import TraceManager, InsnEvent, LoadEvent, SyscallRetEvent, ImageMapEvent
from .debugger import TraceDebugger

_l = logging.getLogger(name=__name__)


#pylint:disable=abstract-method,arguments-differ
class NoSyscallEffectMixin(SuccessorsMixin, ProcedureMixin):
    def process_successors(self, successors, **kwargs):
        state = self.state
        # we have at this point entered the next step so we need to check the previous jumpkind
        if (not state.history
            or not state.history.parent
            or not state.history.parent.jumpkind
            or not state.history.parent.jumpkind.startswith('Ijk_Sys')):
            return super().process_successors(successors, **kwargs)
        successors.processed = True


class InspectEngine(NoSyscallEffectMixin, SimInspectMixin, HeavyVEXMixin):
    pass


class AngrTraceDebugger(TraceDebugger):
    """
    Debugger-like interface for trace playback that can create angr states.
    """

    def __init__(self, tm: TraceManager, project: Optional[angr.Project] = None):
        super().__init__(tm)

        if project is None:
            _l.info('Creating project from mapped images in trace')
            mappings = [e for e in tm.trace if isinstance(e, ImageMapEvent)]
            main_binary = mappings[0]
            libs = mappings[1:] if len(mappings) > 1 else []
            ld_opts = {'main_opts': {'base_addr': main_binary.addr},
                       'auto_load_libs': False,
                       'force_load_libs': [os.path.realpath(lib.name) for lib in libs],
                       'lib_opts': {os.path.realpath(lib.name): {'base_addr': lib.addr} for lib in libs},
            }
            project = angr.Project(main_binary.name, load_options=ld_opts)

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
        _l.info('Rewind to last BB ' + str(bb))
        state = self.state.snapshot()
        state = self._tm.replay(state, bb)

        load_events = {}
        syscall_events = {}
        last_insn = None
        for event in self._tm.trace[bb.eid:self.state.event.eid+1]:
            _l.info(event)
            if isinstance(event, InsnEvent):
                last_insn = event.addr
                load_events[last_insn] = []
            elif isinstance(event, LoadEvent):
                load_events[last_insn].append(event)
            elif isinstance(event, SyscallRetEvent):
                syscall_events[last_insn] = event

        # Slow memory store to state
        # FIXME: replace with faster, no-copy version...
        simstate = self.project.factory.blank_state()
        def get_contiguous_range(f):
            start, i = None, 0
            for k in sorted(f):
                if start is None:
                    start, i = k, 1
                elif k == (start + i):
                    i += 1
                else:
                    yield (start, i)
                    start, i = k, 1
            if i > 0:
                yield (start, i)
        for addr,size in get_contiguous_range(state.mem.keys()):
            simstate.memory.store(addr, bytes(state.mem[i] for i in range(addr, addr+size)))

        # FIXME: Some registers are not modeled here (e.g. FS), so execution may be incorrect
        #        Need to model rflags
        # FIXME: Should determine register list from arch structure (it maps GDB's listing)
        dregs = ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15', 'pc', 'eflags')
        for i, name in enumerate(dregs):
            setattr(simstate.regs, name, bb.regs[i])

        simstate.regs.cc_op = 0 # Copy
        simstate.regs.cc_dep1 = bb.regs[17]
        simstate.regs.cc_dep2 = 0
        simstate.regs.cc_ndep = 0

        # Gather all loads executed by each instruction, and write them just in
        # time to state memory before executing the instruction.
        def before_insn_exec(state):
            _l.info('Executing @ ' + str(state.regs.pc))
            for event in load_events[state.solver.eval(state.regs.pc)]:
                _l.info('   -> ' + str(event))
                state.memory.store(event.addr, event.value, size=event.size)

        simstate.inspect.b('instruction', when=angr.BP_BEFORE, action=before_insn_exec)

        def update_syscall_state(state):
            # XXX: Should use BP_AFTER with original IP
            pc = state.solver.eval(state.regs.pc)
            if pc in syscall_events:
                state.regs.rax = syscall_events[pc].ret
        simstate.inspect.b('instruction', when=angr.BP_BEFORE, action=update_syscall_state)

        insns = [e for e in self._tm.trace[bb.eid:self.state.event.eid] if isinstance(e, InsnEvent)]
        if len(insns) == 0:
            return simstate

        _l.info('Block Instructions:')
        insn_data = b''
        for insn in insns:
            _l.info(' - ' + str(insn))
            insn_data += insn.ibytes

        _l.info('Lifting Block:')
        irsb = pyvex.IRSB(insn_data, bb.addr, self.project.arch)
        _l.info('%s', irsb)

        # XXX: We are executing w/ Vex engine, but it might as well be Unicorn.
        #      It's typically only a handful of instructions.
        _l.info('Executing @ ' + str(simstate.regs.pc))
        _l.info('Executing up to ' + str(self.state.event))
        sim_successors = InspectEngine(None).process(simstate, irsb=irsb)
        if len(sim_successors.successors) != 1:
            _l.warning('!!! Unexpected number of successors: %d (%d total)' % (len(sim_successors.successors), len(sim_successors.all_successors)))
            for s in sim_successors.all_successors:
                _l.info('--> ' + str(s) + ('(unsat)' if s in sim_successors.unsat_successors else ''))

        return sim_successors.all_successors[0]
