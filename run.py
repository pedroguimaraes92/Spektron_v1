# C:\Users\pedro\Desktop\spektron\run.py
import sys
import runpy
from pathlib import Path


def _bootstrap_sys_path() -> tuple[Path, Path]:
    """
    Ensures imports work in BOTH styles:
      - python run.py correlation.graph.build_graph
      - python run.py spektron.correlation.graph.build_graph

    This is done by adding:
      1) PROJECT_DIR  ( ...\Desktop\spektron )
      2) PROJECT_PARENT ( ...\Desktop )
    """
    project_dir = Path(__file__).resolve().parent
    project_parent = project_dir.parent

    # Put both at the front to dominate any accidental same-name folders elsewhere
    for p in (str(project_dir), str(project_parent)):
        if p not in sys.path:
            sys.path.insert(0, p)

    return project_dir, project_parent


def _normalize_module_name(module: str) -> str:
    """
    Accept both:
      spektron.correlation.graph.build_graph
      correlation.graph.build_graph

    If user passes spektron.*, keep it.
    If user passes correlation.* etc, keep it.
    """
    module = module.strip()
    if not module:
        raise SystemExit("Usage: python run.py <module.path>   (e.g. correlation.graph.build_graph)")
    return module


def main():
    _bootstrap_sys_path()

    if len(sys.argv) < 2:
        raise SystemExit("Usage: python run.py <module.path>")

    module = _normalize_module_name(sys.argv[1])

    # Run as __main__ so scripts behave like executed files
    runpy.run_module(module, run_name="__main__")


if __name__ == "__main__":
    main()
