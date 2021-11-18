import logging
if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

import code
import os.path
from argparse import ArgumentParser
from bintrace import TraceManager, ImageMapEvent
from bintrace.debugger import TraceDebugger

try:
    import angr
    from bintrace.debugger_angr import AngrTraceDebugger
except ImportError:
    angr = None

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
            _l.info('angr is not installed, creating basic debugger')
            d = TraceDebugger(tm)
        else:
            d = AngrTraceDebugger(tm)

        if IPython is None:
            _l.info('IPython is not installed, using standard interactive console')
            code.interact()
        else:
            IPython.embed()
    else:
        for ev in tm.trace:
            print(str(ev))


if __name__ == '__main__':
    main()
