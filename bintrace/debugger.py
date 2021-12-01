from typing import Optional, Set
import logging

from .tracemgr import TraceManager, MemoryState, TraceEvent

_l = logging.getLogger(name=__name__)


class TraceDebugger:
    """
    Debugger-like interface for trace playback. Allows setting breakpoints, continuing, etc.
    """

    def __init__(self, tm: TraceManager):
        self._tm: TraceManager = tm
        self.state: MemoryState = None
        self.breakpoints: Set[int] = set()

    def add_breakpoint(self, addr: int):
        """
        Add a new breakpoint.
        """
        self.breakpoints.add(addr)

    def remove_breakpoint(self, addr: int):
        """
        Remove a breakpoint.
        """
        self.breakpoints.remove(addr)

    def _get_prev_stop_event(self) -> Optional[TraceEvent]:
        """
        Get most recent event that should cause reverse execution to stop (e.g. breakpoints).
        """
        if self.state is None:
            return None
        stop_events = set()
        for addr in self.breakpoints:
            e = self._tm.get_prev_exec_event(self.state.event, addr)
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
        for addr in self.breakpoints:
            e = self._tm.get_next_exec_event(self.state.event if self.state else None, addr)
            if e is not None:
                stop_events.add(e)
        if len(stop_events) > 0:
            return min(stop_events, key=lambda e: e.handle)
        return None

    @property
    def can_step_forward(self) -> bool:
        return not self._tm.is_at_end(self.state)

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
        return not self._tm.is_at_start(self.state)

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
        return not self._tm.is_at_end(self.state)

    def continue_forward(self):
        """
        Continue trace playback until some stopping event (e.g. breakpoint).
        """
        self.state = self._tm.replay(self.state, self._get_next_stop_event())
        _l.info('Stopped at %s', self.state.event)

    @property
    def can_continue_backward(self) -> bool:
        return not self._tm.is_at_start(self.state)

    def continue_backward(self):
        """
        Continue trace playback in reverse until some stopping event (e.g. breakpoint).
        """
        self.state = self._tm.replay(self.state, self._get_prev_stop_event())
        _l.info('Stopped at %s', self.state.event)
