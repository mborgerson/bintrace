from typing import Optional, Sequence, Tuple
import logging
import mmap
import copy

from bintrace_native import NativeTrace, State as NativeState  # pylint:disable=no-name-in-module

# Following modules are generated at install time by flatc
# pylint:disable=import-error
from .events import (
    FBEvent,
    FBEventUnion,
    FBImageMapEvent,
    FBInsnEvent,
    FBMemoryEvent,
    FBBlockEvent,
    FBSyscallEvent,
    FBSyscallRetEvent,
    FBVcpuInitEvent,
    FBVcpuExitEvent,
)

_l = logging.getLogger(name=__name__)

EventHandle = int
INVALID_EVENT_HANDLE = EventHandle(0xffffffffffffffff)
VCPU_ANY = 0xffffffff


class TraceEvent:
    """
    Base class for all trace events.
    """

    def __init__(self):
        self.handle: EventHandle = INVALID_EVENT_HANDLE


class ImageMapEvent(TraceEvent, FBImageMapEvent):
    """
    Image map event.
    """

    def __repr__(self):
        return f'<ImageMap name="{self.Name()}" offset={self.Offset():#x} base={self.Base():#x} size={self.Size():#x}>'


class BlockEvent(TraceEvent, FBBlockEvent):
    """
    Start of execution of basic block event.
    """

    def __repr__(self):
        return f'<BlockEvent vcpu={self.Vcpu()} addr={self.Addr():#x}>'


class InsnEvent(TraceEvent, FBInsnEvent):
    """
    Instruction execution event.
    """

    def __repr__(self):
        return f'<InsnEvent vcpu={self.Vcpu()} addr={self.Addr():#x} mnem={self.Mnem()}>'


class MemoryEvent(TraceEvent, FBMemoryEvent):
    """
    Memory store event.
    """

    def __repr__(self):
        s = f'<MemoryEvent [{("Load", "Store")[self.IsStore()]}] vcpu={self.Vcpu()} addr={self.Addr():#x} '
        if self.DataLength():
            s += f'size={self.DataLength()} bytes={repr(bytes(self.Data(i) for i in range(self.DataLength())))}'
        else:
            s += f'size={1<<self.Size()}, val={self.Value()}'
        return s + '>'

    def covers(self, addr: int) -> bool:
        """
        Return True if `addr` is affected by this event.
        """
        sz = self.DataLength() if self.DataLength() else (1 << self.Size())
        return self.Addr() <= addr < (self.Addr() + sz)


class SyscallEvent(TraceEvent, FBSyscallEvent):
    """
    Syscall event.
    """

    def __repr__(self):
        return f'<SyscallEvent vcpu={self.Vcpu()} num={self.Num()}>'


class SyscallRetEvent(TraceEvent, FBSyscallRetEvent):
    """
    Return from syscall event.
    """

    def __repr__(self):
        return f'<SyscallRetEvent vcpu={self.Vcpu()} num={self.Num()} ret={self.Ret()}>'


class VcpuInitEvent(TraceEvent, FBVcpuInitEvent):
    """
    VCPU initialized event.
    """

    def __repr__(self):
        return f'<VcpuInitEvent vcpu={self.Vcpu()}>'


class VcpuExitEvent(TraceEvent, FBVcpuExitEvent):
    """
    VCPU exited event.
    """

    def __repr__(self):
        return f'<VcpuExitEvent vcpu={self.Vcpu()}>'


class MemoryState:
    """
    Minimal memory model for trace playback.
    """
    def __init__(self, native_state: NativeState, event: Optional[TraceEvent]):
        self._ns: NativeState = native_state
        self.event_count: int = self._ns.ev_count
        self.event: TraceEvent = event  # Event that this state reflects all changes up to, but not including
        self._ranges: Optional[Sequence[Tuple[int, int]]] = None
        assert event is None or (self.event.handle == self._ns.ev)

    def get_bytes(self, addr: int, size: int):
        """
        Load a bytestring.
        """
        return bytes(self._ns[i] for i in range(addr, addr+size))

    def get_int(self, addr: int, size: int, endness: str = 'little'):
        """
        Load an integer.
        """
        return int.from_bytes(self.get_bytes(addr, size), endness)

    def snapshot(self):
        """
        Create a copy of this memory state.
        """
        return MemoryState(copy.copy(self._ns), self.event)

    def _gen_contigous_ranges(self):
        """
        Generate the list of contiguous memory ranges in self.mem
        """
        start, i = None, 0
        for k in sorted(self._ns.mem):
            if start is None:
                start, i = k, 1
            elif k == (start + i):
                i += 1
            else:
                yield (start, i)
                start, i = k, 1
        if i > 0:
            yield (start, i)

    def get_contiguous_ranges(self):
        """
        Generate the list of contiguous memory ranges in self.mem
        """
        if self._ranges is None:
            self._ranges = list(self._gen_contigous_ranges())
        return self._ranges


class Trace:
    """
    Manages trace playback.
    """

    def __init__(self):
        self._f = None
        self._ntm = None
        self._mm = None
        self.path = None
        self.checkpoints = []
        self.max_checkpoints = 10

    def _handle_to_event(self, handle):
        if handle == INVALID_EVENT_HANDLE:
            return None
        ev_cls_map = {
            FBEventUnion.imageMapEvent: ImageMapEvent,
            FBEventUnion.blockEvent: BlockEvent,
            FBEventUnion.insnEvent: InsnEvent,
            FBEventUnion.memoryEvent: MemoryEvent,
            FBEventUnion.syscallEvent: SyscallEvent,
            FBEventUnion.syscallRetEvent: SyscallRetEvent,
            FBEventUnion.vcpuInitEvent: VcpuInitEvent,
            FBEventUnion.vcpuExitEvent: VcpuExitEvent,
        }

        ev = FBEvent.GetRootAsEvent(self._mm, handle + 4)
        ev_obj = ev_cls_map[ev.EventType()]()
        ev_obj.handle = handle
        ev_obj.Init(ev.Event().Bytes, ev.Event().Pos)
        return ev_obj

    def load_trace(self, path: str):
        """
        Load trace from file.
        """
        self.path = path
        self._f = open(path, 'r+b')  # pylint:disable=consider-using-with
        self._f.seek(0, 2)
        e = self._f.tell()
        self._f.seek(0)
        self._ntm = NativeTrace(self._f.fileno(), e)
        self._mm = mmap.mmap(self._f.fileno(), 0)

    def get_num_events(self) -> int:
        return self._ntm.get_num_events()

    def get_nth_event(self, n: int) -> Optional[TraceEvent]:
        return self._handle_to_event(self._ntm.get_nth_event(n))

    def get_first_event(self) -> Optional[TraceEvent]:
        return self._handle_to_event(self._ntm.get_first_event())

    def get_last_event(self) -> Optional[TraceEvent]:
        return self._handle_to_event(self._ntm.get_last_event())

    def get_next_event(self, event: TraceEvent) -> Optional[TraceEvent]:
        return self._handle_to_event(self._ntm.get_next_event(event.handle))

    def get_prev_event(self, event: TraceEvent) -> Optional[TraceEvent]:
        return self._handle_to_event(self._ntm.get_prev_event(event.handle))

    def get_next_event_in_direction(self, start: Optional[EventHandle], forward: bool) -> Optional[TraceEvent]:
        if start is None:
            return self.get_first_event() if forward else self.get_last_event()
        else:
            return self.get_next_event(start) if forward else self.get_prev_event(start)

    def get_next_exec_event(self, event: Optional[TraceEvent] = None,
                                  addr: Optional[int] = None,
                                  vcpu: int = VCPU_ANY) -> Optional[InsnEvent]:
        """
        Get next execution event.
        """
        start = self._ntm.get_next_event(event.handle) if event else self._ntm.get_first_event()
        if addr is None:
            h = self._ntm.filter_type(start, FBEventUnion.insnEvent, True, vcpu)
        else:
            h = self._ntm.filter_exec_addr(start, addr, True, vcpu)
        return self._handle_to_event(h)

    def get_prev_exec_event(self, event: TraceEvent,
                                  addr: Optional[int] = None,
                                  vcpu: int = VCPU_ANY) -> Optional[InsnEvent]:
        """
        Get most recent execution event.
        """
        start = self._ntm.get_prev_event(event.handle) if event else self._ntm.get_last_event()
        if addr is None:
            h = self._ntm.filter_type(start, FBEventUnion.insnEvent, False, vcpu)
        else:
            h = self._ntm.filter_exec_addr(start, addr, False, vcpu)
        return self._handle_to_event(h)

    def get_prev_bb_event(self, event: TraceEvent, vcpu: int = VCPU_ANY) -> Optional[BlockEvent]:
        """
        Get most recent BlockEvent event.
        """
        return self._handle_to_event(
            self._ntm.filter_type(self._ntm.get_prev_event(event.handle), FBEventUnion.blockEvent, False, vcpu))

    def filter_exec_addr(self, addr: int, after: Optional[TraceEvent] = None, vcpu: int = VCPU_ANY):
        """
        Get all execution events for this instruction.
        """
        if after is None:
            h = self._ntm.get_first_event()
        else:
            h = self._ntm.get_next_event(after.handle)

        h = self._ntm.filter_exec_addr(h, addr, True, vcpu)
        while not self._ntm.event_handle_invalid(h):
            yield self._handle_to_event(h)
            h = self._ntm.filter_exec_addr(self._ntm.get_next_event(h), addr, True, vcpu)

    def get_next_memory_event_in_direction(self, addr: int, len_: int, store: bool, forward: bool = True,
                                           start: Optional[TraceEvent] = None, vcpu: int = VCPU_ANY):
        """
        Get next load/store to an address.
        """
        e = self.get_next_event_in_direction(start, forward)
        if e is None:
            return e
        else:
            return self._handle_to_event(
                self._ntm.filter_memory(e.handle, addr, len_, store, forward, vcpu)
                )

    def filter_memory(self, addr: int, len_: int, store: bool, forward: bool = True,
                      start: Optional[TraceEvent] = None, vcpu: int = VCPU_ANY):
        """
        Generate all loads/stores to byte address.
        """
        e = start
        while True:
            e = self.get_next_memory_event_in_direction(addr, len_, store, forward, e, vcpu)
            if e is None:
                break
            yield e

    def filter_image_map(self):
        h = self._ntm.filter_type(self._ntm.get_first_event(), FBEventUnion.imageMapEvent, True, VCPU_ANY)
        while not self._ntm.event_handle_invalid(h):
            yield self._handle_to_event(h)
            h = self._ntm.filter_type(self._ntm.get_next_event(h), FBEventUnion.imageMapEvent, True, VCPU_ANY)

    def replay(self, state: Optional[MemoryState] = None,
                     until: Optional[TraceEvent] = None) -> MemoryState:
        """
        Replay trace from `state` up to, but not including, `until` trace event.

        `until` may be an event that happened before current `state`.
        """
        until_handle = until.handle if until else INVALID_EVENT_HANDLE
        reverse = state and (state.event is None or until_handle < state.event.handle)
        if reverse:
            state = None

        # Check checkpoint cache to see if any recent replays are available
        candidates = [s for s in self.checkpoints if s.event.handle <= until_handle]
        if len(candidates):
            _l.info('Checkpoint cache hit!')
            state = max(candidates, key=lambda s: s.event.handle)
            self.checkpoints.remove(state)
            self.checkpoints.insert(0, state)
        else:
            _l.info('Checkpoint cache miss!')

        if state and state.event.handle == until_handle:
            _l.info('Provided state is target state')
            return state

        _l.info('Replaying from %s to %s%s',
                    state.event if state else 'start',
                    until if until else 'end',
                    ' (Reversed)' if reverse else '')
        if state:
            ns = self._ntm.replay_from_state_until(state._ns, until_handle)
        else:
            ns = self._ntm.replay_until(until_handle)

        state = MemoryState(ns, self._handle_to_event(ns.ev))

        if state.event is not None:
            self.checkpoints.insert(0, state)
            self.checkpoints = self.checkpoints[0:self.max_checkpoints-1]

        return state

    @staticmethod
    def is_at_end(state: MemoryState) -> bool:
        return state.event is None

    def is_at_start(self, state: MemoryState) -> bool:
        return state.event and state.event.handle == self._ntm.get_first_event()
