from __future__ import annotations

from typing import Any, Dict, List, Optional
import socket

def _uniq(xs: List[Any]) -> List[Any]:
    out = []
    seen = set()
    for x in xs:
        k = str(x)
        if k in seen:
            continue
        seen.add(k)
        out.append(x)
    return out

def probe_dns(host: str) -> Dict[str, Any]:
    """Best-effort DNS probe: A/AAAA via getaddrinfo; CNAME/MX/TXT via dnspython if available."""
    res: Dict[str, Any] = {
        "ok": False,
        "a": [],
        "aaaa": [],
        "cname": [],
        "mx": [],
        "txt": [],
    }

    # A/AAAA
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        a, aaaa = [], []
        for fam, _, _, _, sockaddr in infos:
            ip = sockaddr[0]
            if fam == socket.AF_INET:
                a.append(ip)
            elif fam == socket.AF_INET6:
                aaaa.append(ip)
        res["a"] = _uniq(a)
        res["aaaa"] = _uniq(aaaa)
    except Exception:
        pass

    # Optional richer records
    try:
        import dns.resolver  # type: ignore
        import dns.rdatatype  # type: ignore

        r = dns.resolver.Resolver()
        # CNAME
        try:
            ans = r.resolve(host, "CNAME")
            res["cname"] = _uniq([str(x.target).rstrip(".") for x in ans])
        except Exception:
            res["cname"] = []
        # MX
        mx_items = []
        try:
            ans = r.resolve(host, "MX")
            for x in ans:
                mx_items.append({"exchange": str(x.exchange).rstrip("."), "preference": getattr(x, "preference", None)})
        except Exception:
            mx_items = []
        res["mx"] = mx_items
        # TXT
        txt_items = []
        try:
            ans = r.resolve(host, "TXT")
            for x in ans:
                # dnspython returns list of byte strings per record
                chunks = []
                for c in getattr(x, "strings", []) or []:
                    try:
                        chunks.append(c.decode("utf-8", "ignore"))
                    except Exception:
                        chunks.append(str(c))
                txt_items.append("".join(chunks) if chunks else str(x))
        except Exception:
            txt_items = []
        res["txt"] = _uniq(txt_items)
    except Exception:
        # dnspython not installed
        pass

    res["ok"] = True if (res.get("a") or res.get("aaaa") or res.get("cname") or res.get("mx") or res.get("txt")) else True
    return res
