from typing import Optional, Set
from enum import Enum
import logging

from .tracemgr import Trace, MemoryState, TraceEvent


_l = logging.getLogger(name=__name__)


class BreakpointType(Enum):
    """
    Type of breakpoint.
    """

    Execute = 1
    Read = 2
    Write = 4


class Breakpoint:
    """
    A breakpoint / watchpoint.
    """

    __slots__ = (
        'type', 'addr', 'length', 'comment'
    )

    def __init__(self, type_: BreakpointType, addr: int, length: int = 1, comment: str = ''):
        self.type: BreakpointType = type_
        self.addr: int = addr
        self.length: int = length
        self.comment: str = comment


class TraceDebugger:
    """
    Debugger-like interface for trace playback. Allows setting breakpoints, continuing, etc.
    """

    def __init__(self, tm: Trace):
        self._tm: Trace = tm
        self.state: MemoryState = None
        self.breakpoints: Set[Breakpoint] = set()

    def _get_prev_stop_event(self) -> Optional[TraceEvent]:
        """
        Get most recent event that should cause reverse execution to stop (e.g. breakpoints).
        """
        if self.state is None:
            return None
        stop_events = set()
        for bp in self.breakpoints:
            if bp.type == BreakpointType.Execute:
                e = self._tm.get_prev_exec_event(self.state.event, bp.addr)
            # elif bp.type == BreakpointType.Read:
            #     e = self._tm.get_prev_
            if e is not None:
                stop_events.add(e)
        if len(stop_events) > 0:
            return max(stop_events, key=lambda e: e.handle)
        return self._tm.get_first_event()

    def _get_next_stop_event(self) -> Optional[TraceEvent]:
        """
        Get next event that should cause execution to stop (e.g. breakpoints).
        """
        stop_events = set()
        for bp in self.breakpoints:
            if bp.type == BreakpointType.Execute:
                e = self._tm.get_next_exec_event(self.state.event if self.state else None, bp.addr)
            if e is not None:
                stop_events.add(e)
        if len(stop_events) > 0:
            return min(stop_events, key=lambda e: e.handle)
        return None

    @property
    def can_step_forward(self) -> bool:
        return self.state is None or not self._tm.is_at_end(self.state)

    def step_forward(self, count=1):
        """
        Step forward by 1 machine instruction.
        """
        until = self.state.event if self.state else None
        for _ in range(count):
            until = self._tm.get_next_exec_event(until)

        self.state = self._tm.replay(state=self.state, until=until)

    @property
    def can_step_backward(self) -> bool:
        return self.state is not None and not self._tm.is_at_start(self.state)

    def step_backward(self, count=1):
        """
        Step backward by 1 machine instruction.
        """
        until = self.state.event if self.state else None
        for _ in range(count):
            until = self._tm.get_prev_exec_event(until)

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
