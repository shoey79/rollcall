"""Exit 0 if the add-on code that builds the agent script or installer changed between two commits.

Used by the Tests workflow: the Windows jobs run when the agent or this code changes. Compares the
functions themselves, so other edits to main.py don't count."""
import ast
import subprocess
import sys

FUNCS = {"build_agent_script", "_script_version"}


def funcs(rev: str) -> dict:
    try:
        src = subprocess.run(["git", "show", f"{rev}:rollcall/app/main.py"], capture_output=True, text=True, check=True).stdout
    except subprocess.CalledProcessError:
        return {}
    tree = ast.parse(src)
    return {n.name: ast.get_source_segment(src, n) for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name in FUNCS}


before, after = funcs(sys.argv[1]), funcs(sys.argv[2])
sys.exit(0 if not before or before != after else 1)
