# FIXME: Allow keeping trace file on disk and replaying from it
# FIXME: Checkpoints
from typing import Union, Mapping, Sequence, Optional
from collections import defaultdict
import os.path
import logging
import capnp

_l = logging.getLogger(name=__name__)
capnp.remove_import_hook()  # pylint:disable=no-member
proto_path = os.path.join(os.path.dirname(__file__), 'trace.capnp')
proto_capnp = capnp.load(proto_path)  # pylint:disable=no-member


class TraceEvent:
    """
    Base class for all trace events.
    """

    def __init__(self):
        self.eid: int = -1


class ImageMapEvent(TraceEvent):
    """
    Image map event.
    """

    __slots__ = ('name', 'addr')

    def __init__(self, name: str, addr: int):
        super().__init__()
        self.name = name
        self.addr = addr

    def __repr__(self):
        return f'<ImageMap name="{self.name}" base={self.addr:#x}>'


class BlockEvent(TraceEvent):
    """
    Start of execution of basic block event.
    """

    __slots__ = ('vcpu', 'addr', 'regs')

    def __init__(self, vcpu: int, addr: int, regs: Sequence[int]):
        super().__init__()
        self.vcpu: int = vcpu
        self.addr: int = addr
        self.regs: Sequence[int] = regs

    def __repr__(self):
        return f'<BlockEvent vcpu={self.vcpu} addr={self.addr:#x}>'


class InsnEvent(TraceEvent):
    """
    Instruction execution event.
    """

    __slots__ = ('vcpu', 'addr', 'ibytes', 'mnem')

    def __init__(self, vcpu: int, addr: int, ibytes: bytes, mnem: str):
        super().__init__()
        self.vcpu: int = vcpu
        self.addr: int = addr
        self.ibytes: bytes = ibytes
        self.mnem: str = mnem

    def __repr__(self):
        return f'<InsnEvent vcpu={self.vcpu} addr={self.addr:#x} mnem=\'{self.mnem}\'>'


class LoadEvent(TraceEvent):
    """
    Memory load event.
    """

    __slots__ = ('vcpu', 'addr', 'size', 'value')

    def __init__(self, vcpu: int, addr: int, size: int, value: int):
        super().__init__()
        self.vcpu: int = vcpu
        self.addr: int = addr
        self.size: int = size
        self.value: int = value

    def __repr__(self):
        return f'<LoadEvent vcpu={self.vcpu} addr={self.addr:#x} size={self.size} value={self.value:#x}>'


class StoreEvent(TraceEvent):
    """
    Memory store event.
    """

    __slots__ = ('vcpu', 'addr', 'size', 'value', 'value_inv')

    def __init__(self, vcpu: int, addr: int, size: int, value: Union[int, bytes]):
        super().__init__()
        self.vcpu: int = vcpu
        self.addr: int = addr
        self.size: int = size
        self.value: Union[int, bytes] = value
        self.value_inv: Optional[bytes] = None  # Original value before store event, for reverse playback

    def __repr__(self):
        vrepr = f'{self.value:x}' if isinstance(self.value, int) else repr(self.value)
        s = f'<StoreEvent vcpu={self.vcpu} addr={self.addr:#x}' + \
            f' size={self.size} value={vrepr}>'
        return s

    def covers(self, addr: int) -> bool:
        """
        Return True if `addr` is affected by this event.
        """
        return self.addr <= addr < (self.addr + self.size)


class SyscallEvent(TraceEvent):
    """
    Syscall event.
    """

    __slots__ = ('vcpu', 'num')

    def __init__(self, vcpu: int, num: int):
        super().__init__()
        self.vcpu: int = vcpu
        self.num: int = num

    def __repr__(self):
        return f'<SyscallEvent vcpu={self.vcpu} num={self.num}>'


class SyscallRetEvent(TraceEvent):
    """
    Return from syscall event.
    """

    __slots__ = ('vcpu', 'num', 'ret')

    def __init__(self, vcpu: int, num: int, ret: int):
        super().__init__()
        self.vcpu: int = vcpu
        self.num: int = num
        self.ret: int = ret

    def __repr__(self):
        return f'<SyscallRetEvent vcpu={self.vcpu} num={self.num} ret={self.ret}>'


class TraceStartEvent(TraceEvent):
    """
    Marks the start of the trace.
    """

    def __repr__(self):
        return '<TraceStartEvent>'


class TraceEndEvent(TraceEvent):
    """
    Marks the end of the trace.
    """

    def __repr__(self):
        return '<TraceEndEvent>'


class MemoryState:
    """
    Minimal memory model for trace playback.
    """
    def __init__(self, mem: Optional[Mapping[int, int]] = None,
                       event: Optional[TraceEvent] = None):
        self.mem = mem or defaultdict(int)  # FIXME: Default dict should return INVALID byte by default.
        self.event: TraceEvent = event  # Event that this state reflects all changes up to, but not including

    def set_bytes(self, addr: int, data: bytes):
        """
        Store a bytestring.
        """
        for i in range(addr, addr+len(data)):
            self.mem[i] = data[i-addr]

    def set_int(self, addr: int, size: int, val: int):
        """
        Store an integer.
        """
        val &= (1<<(size*8))-1
        self.set_bytes(addr, val.to_bytes(size, 'little'))

    def get_bytes(self, addr: int, size: int):
        """
        Load a bytestring.
        """
        return bytes(self.mem[i] for i in range(addr, addr+size))

    def get_int(self, addr: int, size: int):
        """
        Load an integer.
        """
        return int.from_bytes(self.get_bytes(addr, size), 'little')

    def set(self, addr: int, size: int, val: Union[int, bytes]):
        """
        Store a bytestring or integer.
        """
        if isinstance(val, int):
            self.set_int(addr, size, val)
        else:
            self.set_bytes(addr, val)

    def snapshot(self):
        """
        Create a copy of this memory state.
        """
        return MemoryState(self.mem.copy(), self.event)


class TraceManager:
    """
    Manages trace playback.
    """

    def __init__(self):
        self.trace: Sequence[TraceEvent] = []
        self.last_pos = 0

    def _add_imageMapEvent(self, bev):
        bev = bev.imageMapEvent
        e = ImageMapEvent(bev.name, bev.base)
        e.eid = len(self.trace)
        self.trace.append(e)

    def _add_blockEvent(self, bev):
        bev = bev.blockEvent
        e = BlockEvent(bev.vcpu, bev.addr, bev.regs)
        e.eid = len(self.trace)
        self.trace.append(e)

    def _add_insnEvent(self, bev):
        bev = bev.insnEvent
        e = InsnEvent(bev.vcpu, bev.addr, bev.bytes, bev.mnem)
        e.eid = len(self.trace)
        self.trace.append(e)

    def _add_memoryEvent(self, bev):
        bev = bev.memoryEvent
        t = bev.which()
        if t == 'bytes':
            v, s = bev.bytes, len(bev.bytes)
        elif t == 'ui8':
            v, s = bev.ui8, 1
        elif t == 'ui16':
            v, s = bev.ui16, 2
        elif t == 'ui32':
            v, s = bev.ui32, 4
        elif t == 'ui64':
            v, s = bev.ui64, 8
        else:
            assert False

        if bev.isStore:
            e = StoreEvent(bev.vcpu, bev.addr, s, v)
        else:
            e = LoadEvent(bev.vcpu, bev.addr, s, v)

        e.eid = len(self.trace)
        self.trace.append(e)

    def _add_syscallEvent(self, bev):
        bev = bev.syscallEvent
        e = SyscallEvent(bev.vcpu, bev.num)
        e.eid = len(self.trace)
        self.trace.append(e)

    def _add_syscallRetEvent(self, bev):
        bev = bev.syscallRetEvent
        e = SyscallRetEvent(bev.vcpu, bev.num, bev.ret)
        e.eid = len(self.trace)
        self.trace.append(e)

    def load_trace(self, path: str, update: bool = False):
        """
        Load trace from file.
        """
        _l.info('Loading trace events...')
        if not update or len(self.trace) == 0:
            r = TraceStartEvent()
            r.eid = 0
            self.trace = [r]
        else:
            self.trace.pop(len(self.trace)-1)  # Trim end event

        handler_table = {
            'imageMapEvent'   : self._add_imageMapEvent,
            'blockEvent'      : self._add_blockEvent,
            'insnEvent'       : self._add_insnEvent,
            'memoryEvent'     : self._add_memoryEvent,
            'syscallEvent'    : self._add_syscallEvent,
            'syscallRetEvent' : self._add_syscallRetEvent,
        }

        with open(path, 'rb') as f:
            if update:
                f.seek(self.last_pos)
            for ev in proto_capnp.Event.read_multiple_packed(f):
                handler_table[ev.which()](ev)
            self.last_pos = f.tell()

        r = TraceEndEvent()
        r.eid = len(self.trace)
        self.trace.append(r)

        _l.info('Building reverse trace...')
        state = MemoryState()
        for event in self.trace:
            if isinstance(event, StoreEvent):
                event: StoreEvent  # XXX: Fix pylint incorrect type inference
                event.value_inv = state.get_bytes(event.addr, event.size)
                state.set(event.addr, event.size, event.value)

    def get_next_exec_event(self, event: TraceEvent, addr: Optional[int] = None) -> Optional[InsnEvent]:
        """
        Get next execution event.
        """
        if addr is None:
            cond = lambda e: isinstance(e, InsnEvent)
        else:
            cond = lambda e: isinstance(e, InsnEvent) and e.addr == addr

        for i in range(event.eid + 1, len(self.trace)):
            e = self.trace[i]
            if cond(e):
                return e

        return None

    def get_prev_exec_event(self, event: TraceEvent, addr: Optional[int] = None) -> Optional[InsnEvent]:
        """
        Get most recent execution event.
        """
        if addr is None:
            cond = lambda e: isinstance(e, InsnEvent)
        else:
            cond = lambda e: isinstance(e, InsnEvent) and e.addr == addr

        for i in range(event.eid - 1, -1, -1):
            e = self.trace[i]
            if cond(e):
                return e

        return None

    def get_prev_bb_event(self, event: TraceEvent) -> Optional[BlockEvent]:
        """
        Get most recent BlockEvent event.
        """
        for i in range(event.eid - 1, -1, -1):
            e = self.trace[i]
            if isinstance(e, BlockEvent):
                return e

        return None

    def filter_exec_addr(self, addr: int, after: Optional[TraceEvent] = None):
        """
        Get all execution events for this instruction.
        """
        start_index = 0 if after is None else (after.eid + 1)
        for e in self.trace[start_index:]:
            if isinstance(e, InsnEvent) and e.addr == addr:
                yield e

    def filter_store(self, addr: int, after: Optional[TraceEvent] = None):
        """
        Get all stores to byte address.
        """
        start_index = 0 if after is None else (after.eid + 1)
        for e in self.trace[start_index:]:
            if isinstance(e, StoreEvent) and e.covers(addr):
                yield e

    def replay(self, state: Optional[MemoryState] = None,
                     until: Optional[TraceEvent] = None) -> MemoryState:
        """
        Replay trace from `state` up to, but not including, `until` trace event.

        Event `until` may be an event that happened before current `state`, in which case the trace will be played in
        reverse to revert `state` back to the state just before `until` event.
        """
        if state is None:
            state = MemoryState()
        if until is None:
            until = self.trace[-1]
        start_event = state.event or self.trace[0]
        start_index = start_event.eid
        reverse = state and state.event and until and until.eid < state.event.eid
        _l.info('Replaying from %s (%d) until %s (%d)%s', start_event, start_index, until, until.eid,
                ' (Reversed)' if reverse else '')

        if reverse:
            # Apply the inverse effects of each event, *including* stop event
            for i in range(start_index - 1, -1, -1):
                event = self.trace[i]
                if isinstance(event, StoreEvent):
                    state.set(event.addr, event.size, event.value_inv)
                state.event = event
                if event is until:
                    break
        else:
            # Apply effects of each event, *not including* stop event
            for i in range(start_index, len(self.trace)):
                event = self.trace[i]
                state.event = event
                if event is until:
                    break
                if isinstance(event, StoreEvent):
                    state.set(event.addr, event.size, event.value)

                # XXX: Consider storing loads and instructions executed to model

        return state

    def is_at_end(self, state: MemoryState) -> bool:
        return state.event is self.trace[-1]

    def is_at_start(self, state: MemoryState) -> bool:
        return state.event is self.trace[0]
