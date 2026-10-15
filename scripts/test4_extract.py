"""Extract DeFiHackLabs incidents for sealed test v4 (text only, nothing executed).

Same parse() as extract_exploits.py, but any 64-hex hash on an "attack tx" header line (phalcon/blocksec/
explorer links), plus hashes on comment lines following a bare "Attack Txs:" line (test3_extract rule).
Incidents whose listed attack txs intersect ANY hash already used by the project are dropped.

    uv run python scripts/test4_extract.py   -> data/test4_incidents.jsonl
"""
import json
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import extract_exploits as ee  # noqa: E402
import test4_chains as tc  # noqa: E402
from test3_extract import continuation_txs  # noqa: E402
from test4_common import used_hashes  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
HASH = re.compile(r"(0x[0-9a-fA-F]{64})")
VICTIM2 = re.compile(r"//\s*(?:Vuln(?:erable)?|Victim)(?:\s*(?:Contract|Pool|Protocol)s?)?\s*:(.*)", re.I)
CHAINS = ["eth", "bsc", "base"] + list(tc.NEW_CHAINS)


def tx_lines(path: Path) -> list[str]:
    """Fallback: hashes on header comment lines mentioning a tx ("// TX : <link>", "// @TX" + next lines,
    "// Tx: <link>", tenderly/phalcon "/tx/" links); used only when the attack-tx rules find nothing."""
    lines = path.read_text(errors="ignore").splitlines()[:60]
    out = []
    for i, ln in enumerate(lines):
        s = ln.strip()
        if not s.startswith("//"):
            continue
        if re.search(r"\btx\b|/tx/", s, re.I):
            out += HASH.findall(s)
            if re.fullmatch(r"//\s*@?txs?\s*:?\s*", s, re.I):
                for nxt in lines[i + 1:i + 6]:
                    if not nxt.strip().startswith("//"):
                        break
                    hs = HASH.findall(nxt)
                    if not hs and re.search(r"[A-Za-z]{4,}\s*:", nxt):
                        break
                    out += hs
    return [h.lower() for h in dict.fromkeys(out)]


def extract(path: Path, chain: str) -> dict | None:
    ee.CHAIN = chain
    ee.TX = HASH
    r = ee.parse(path)
    cont = continuation_txs(path)
    how = "attack_tx_line" if r else ("continuation" if cont else None)
    if r is None and not cont:
        cont = tx_lines(path)
        how = "tx_line_fallback"
    if r is None:
        if not cont:
            return None
        text = path.read_text(errors="ignore")
        fork = ee.FORK[chain]
        if f'createSelectFork("{fork}"' not in text and f"createSelectFork('{fork}'" not in text \
                and not (chain == "eth" and "ETH_RPC_URL" in text):
            return None
        header = "\n".join(text.splitlines()[:60])
        r = {"name": path.stem, "chain": chain, "file": str(path.relative_to(ROOT)), "attack_txs": []}
        for key, rx in ee.FIELDS.items():
            m = rx.search(header)
            if m:
                r[key] = m.group(1).strip() if key == "lost" else [a.lower() for a in ee.ADDR.findall(m.group(1))]
        m = re.search(r"createSelectFork\(\s*[\"']" + fork + r"[\"']\s*,\s*([0-9_]+)", text)
        if m:
            r["fork_block"] = int(m.group(1).replace("_", ""))
        month = path.parent.name
        r["month"] = month if re.fullmatch(r"\d{4}-\d{2}", month) else None
    r["file"] = str(path.relative_to(ROOT))
    r["attack_txs"] = list(dict.fromkeys(r["attack_txs"] + cont))
    r["extractor"] = how
    if not r.get("victim"):  # header variants the frozen FIELDS regex misses ("Vuln Contract", "Victim Contract")
        header = "\n".join(path.read_text(errors="ignore").splitlines()[:60])
        m = VICTIM2.search(header)
        if m and ee.ADDR.findall(m.group(1)):
            r["victim"] = [a.lower() for a in ee.ADDR.findall(m.group(1))]
            r["victim_rule"] = "fallback"
    return r


def main():
    ee.FORK.update(tc.FORK)
    src = ROOT / "data/raw/DeFiHackLabs/src/test"
    files = sorted(src.rglob("*.sol"))
    used = used_hashes()
    out, dropped = [], Counter()
    seen = set()
    for chain in CHAINS:
        for p in files:
            r = extract(p, chain)
            if not r or not r["attack_txs"]:
                continue
            if any(h in used for h in r["attack_txs"]):
                dropped[chain] += 1
                continue
            if r["attack_txs"][0] in seen:
                continue
            seen.add(r["attack_txs"][0])
            out.append(r)
    (ROOT / "data/test4_incidents.jsonl").write_text("".join(json.dumps(r) + "\n" for r in out))
    c = Counter(r["chain"] for r in out)
    print("new incidents per chain:", dict(c))
    print("dropped (attack tx already used):", dict(dropped))
    print("by extractor:", dict(Counter((r["chain"], r["extractor"]) for r in out)))
    print("with victim:", dict(Counter(r["chain"] for r in out if r.get("victim"))))


if __name__ == "__main__":
    main()
