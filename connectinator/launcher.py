"""Route frozen worker invocations before importing or creating the Qt UI."""

import sys


def main():
    args = sys.argv[1:]
    if len(args) == 3 and args[0] == "--arp-worker":
        from .discovery import worker_files
        worker_files(args[1], args[2])
    elif len(args) == 2 and args[0] == "--self-test":
        from .diagnostics import self_test
        self_test(args[1])
    elif args:
        raise SystemExit("Unknown arguments. Use Connectinator without arguments to open the app.")
    else:
        from .app import main as run_app
        run_app()
