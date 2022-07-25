from typing import Optional, Set, Tuple
from enum import Enum
import logging

from .tracemgr import Trace, MemoryState, TraceEvent


_l = logging.getLogger(name=__name__)


class BreakpointType(Enum):
    """
    Type of breakpoint.
    """

    Execute = 0
    Read = 1
    Write = 2


class Breakpoint:
    """
    A breakpoint / watchpoint.
    """

    __slots__ = (
        'type', 'addr', 'size', 'comment'
    )

    def __init__(self, type_: BreakpointType, addr: int, size: int = 1):
        self.type: BreakpointType = type_
        self.addr: int = addr
        self.size: int = size


class TraceDebugger:
    """
    Debugger-like interface for trace playback. Allows setting breakpoints, continuing, etc.
    """

    def __init__(self, tm: Trace, vcpu: int = 0):
        self._tm: Trace = tm
        self.vcpu: int = vcpu
        self.state: MemoryState = None
        self.breakpoints: Set[Breakpoint] = set()
        self.single_step_range: Optional[Tuple[int, int]] = None  # If set, (addr, size) of region to step in. Outside
                                                                  # this range will be stepped through.

    def _get_breakpoint_events_in_direction(self, start: Optional[TraceEvent], forward: bool) -> Set[TraceEvent]:
        events = set()

        for bp in self.breakpoints:
            if bp.type == BreakpointType.Execute:
                if forward:
                    e = self._tm.get_next_exec_event(start, bp.addr, vcpu=self.vcpu)
                else:
                    e = self._tm.get_prev_exec_event(start, bp.addr, vcpu=self.vcpu)
            elif bp.type == BreakpointType.Read:
                e = self._tm.get_next_memory_event_in_direction(
                    bp.addr, bp.size, store=False, forward=forward, start=start, vcpu=self.vcpu)
            elif bp.type == BreakpointType.Write:
                e = self._tm.get_next_memory_event_in_direction(
                    bp.addr, bp.size, store=True, forward=forward, start=start, vcpu=self.vcpu)
            else:
                assert False, 'Unsupported breakpoint type'

            if e is not None:
                events.add(e)

        return events

    def _get_prev_stop_event(self) -> Optional[TraceEvent]:
        """
        Get most recent event that should cause reverse execution to stop (e.g. breakpoints).
        """
        if self.state is None:
            return None
        stop_events = self._get_breakpoint_events_in_direction(self.state.event, forward=False)
        stop_events.add(self._tm.get_first_event())
        return max(stop_events, key=lambda e: e.handle)

    def _get_next_stop_event(self) -> Optional[TraceEvent]:
        """
        Get next event that should cause execution to stop (e.g. breakpoints).
        """
        start_event = self.state.event if self.state else None
        stop_events = self._get_breakpoint_events_in_direction(start_event, forward=True)
        return min(stop_events, key=lambda e: e.handle) if len(stop_events) else None

    @property
    def can_step_forward(self) -> bool:
        return self.state is None or not self._tm.is_at_end(self.state)

    def step_forward(self, count=1, until_addr: Optional[int] = None):
        """
        Step forward by 1 machine instruction.
        """
        until = self.state.event if self.state else None
        if until_addr is not None:
            until = self._tm.get_next_exec_event(until, addr=until_addr, vcpu=self.vcpu)
            count -= 1

        if self.single_step_range is None:
            step_region_addr, step_region_size = None, 1
        else:
            self.single_step_range: Tuple[int, int]
            step_region_addr, step_region_size = self.single_step_range

        for _ in range(count):
            until = self._tm.get_next_exec_event(until, addr=step_region_addr, size=step_region_size, vcpu=self.vcpu)

        self.state = self._tm.replay(state=self.state, until=until)

    @property
    def can_step_backward(self) -> bool:
        return self.state is not None and not self._tm.is_at_start(self.state)

    def step_backward(self, count=1):
        """
        Step backward by 1 machine instruction.
        """
        until = self.state.event if self.state else None

        if self.single_step_range is None:
            step_region_addr, step_region_size = None, 1
        else:
            self.single_step_range: Tuple[int, int]
            step_region_addr, step_region_size = self.single_step_range

        for _ in range(count):
            until = self._tm.get_prev_exec_event(until, addr=step_region_addr, size=step_region_size, vcpu=self.vcpu)

        self.state = self._tm.replay(state=self.state, until=until)

    @property
    def can_continue_forward(self) -> bool:
        return self.state is None or not self._tm.is_at_end(self.state)

    def continue_forward(self):
        """
        Continue trace playback until some stopping event (e.g. breakpoint).
        """
        self.state = self._tm.replay(self.state, self._get_next_stop_event())
        _l.info('Stopped at %s', self.state.event)

    @property
    def can_continue_backward(self) -> bool:
        return self.state is not None and not self._tm.is_at_start(self.state)

    def continue_backward(self):
        """
        Continue trace playback in reverse until some stopping event (e.g. breakpoint).
        """
        self.state = self._tm.replay(self.state, self._get_prev_stop_event())
        _l.info('Stopped at %s', self.state.event)
