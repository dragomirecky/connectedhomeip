# Helper to add sibling Python packages to sys.path at runtime.
# Used by codegen.py and codegen_paths.py to locate py_matter_idl.

import os
import sys


class PythonPath:
    """Context manager that temporarily adds a package directory to sys.path."""

    def __init__(self, package_name, relative_to=None):
        if relative_to:
            base = os.path.dirname(os.path.abspath(relative_to))
        else:
            base = os.path.dirname(os.path.abspath(__file__))
        self.path = os.path.join(base, package_name)

    def __enter__(self):
        if self.path not in sys.path:
            sys.path.insert(0, self.path)
        return self

    def __exit__(self, *args):
        pass
