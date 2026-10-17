"""Organization-owned console entry point."""

import sys


def main():
    try:
        from appsec_analyzer.organization import main as organization_main
    except ImportError:
        print("nordlicht-appsec: install the matching approved engine and dependency wheels", file=sys.stderr)
        return 2
    return organization_main("nordlicht_appsec")


if __name__ == "__main__":
    raise SystemExit(main())
