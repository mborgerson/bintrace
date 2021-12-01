try:
    import angr
except ImportError:
    angr = None

import logging
import code
from argparse import ArgumentParser
from bintrace import TraceManager
from bintrace.debugger import TraceDebugger
if angr is not None:
    from bintrace.debugger_angr import AngrTraceDebugger

try:
    import IPython
except ImportError:
    IPython = None

_l = logging.getLogger(__name__)


def main():
    ap = ArgumentParser(description='Parse a trace file, optionally entering interactive shell for analysis')
    ap.add_argument('path', help='Path to trace file')
    ap.add_argument('-i', '--interactive', default=False, action='store_true', help='Enter interactive shell')
    args = ap.parse_args()

    tm = TraceManager()
    tm.load_trace(args.path)

    if args.interactive:
        if angr is None:
            _l.warning('angr is not installed, creating basic debugger')
            d = TraceDebugger(tm)  # pylint:disable=unused-variable
        else:
            d = AngrTraceDebugger(tm)  # pylint:disable=unused-variable

        if IPython is None:
            _l.warning('IPython is not installed, using standard interactive console')
            code.interact()
        else:
            IPython.embed()
    else:
        ev = tm.get_first_event()
        while ev:
            print(str(ev))
            ev = tm.get_next_event(ev)


if __name__ == '__main__':
    main()
