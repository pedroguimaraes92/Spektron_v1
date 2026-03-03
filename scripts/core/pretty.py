from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
import shutil
import sys

try:
    from colorama import Fore, Style
except Exception:
    class _Dummy:
        RESET_ALL = ""
    class Fore(_Dummy):
        RED = GREEN = YELLOW = CYAN = MAGENTA = BLUE = WHITE = ""
    class Style(_Dummy):
        BRIGHT = DIM = NORMAL = RESET_ALL = ""

def supports_unicode() -> bool:
    enc = (sys.stdout.encoding or "").lower()
    return "utf" in enc

def sym(ok: bool) -> str:
    if supports_unicode():
        return "✅" if ok else "❌"
    return "OK" if ok else "ERR"

def color_sev(sev: str) -> str:
    s = (sev or "").lower()
    if s in ("critical", "high"):
        return Fore.RED + sev + Style.RESET_ALL
    if s in ("medium",):
        return Fore.YELLOW + sev + Style.RESET_ALL
    if s in ("low", "info"):
        return Fore.CYAN + sev + Style.RESET_ALL
    return sev

def hr(char: str = "─") -> str:
    width = shutil.get_terminal_size((100, 20)).columns
    return char * max(20, width)

def box(title: str, lines: Sequence[str]) -> str:
    width = shutil.get_terminal_size((100, 20)).columns
    width = max(60, min(width, 120))
    top = "┌" + "─" * (width - 2) + "┐"
    mid = "├" + "─" * (width - 2) + "┤"
    bot = "└" + "─" * (width - 2) + "┘"
    t = f" {title.strip()} "
    t = t[: width - 4]
    top = "┌" + t.center(width - 2, "─") + "┐"
    out = [top]
    for ln in lines:
        txt = ln.rstrip("\n")
        if len(txt) > width - 4:
            txt = txt[: width - 7] + "..."
        out.append("│ " + txt.ljust(width - 4) + " │")
    out.append(bot)
    return "\n".join(out)

def kv_table(pairs: Sequence[Tuple[str, Any]]) -> List[str]:
    klen = max([len(str(k)) for k, _ in pairs] + [4])
    lines = []
    for k, v in pairs:
        lines.append(f"{str(k).ljust(klen)} : {v}")
    return lines
