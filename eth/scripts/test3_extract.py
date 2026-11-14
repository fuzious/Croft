"""Extract DeFiHackLabs incidents for v3 chains.

Pass 1: the unmodified extract_exploits.py (runtime-extended EXPLORER/FORK maps).
Pass 2 (supplement, marked extractor="broad"): same parse() but any 64-hex hash on an "attack tx" header line
(phalcon/blocksec/raw-hash links), plus hashes on the comment lines directly following a bare "Attack Txs:" line.

    uv run python scripts/test3_extract.py polygon   -> data/test3_exploits_polygon.jsonl
"""
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import extract_exploits as ee  # noqa: E402
import test3_chains as tc  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
HASH = re.compile(r"(0x[0-9a-fA-F]{64})")


def continuation_txs(path: Path) -> list[str]:
    lines = path.read_text(errors="ignore").splitlines()[:60]
    out = []
    for i, ln in enumerate(lines):
        if re.search(r"attack\s*txs?\s*:?\s*$", ln, re.I):
            for nxt in lines[i + 1:i + 6]:
                if not nxt.strip().startswith("//"):
                    break
                hs = HASH.findall(nxt)
                if not hs and re.search(r"[A-Za-z]{4,}\s*:", nxt):
                    break
                out += hs
    return [h.lower() for h in dict.fromkeys(out)]


if __name__ == "__main__":
    chain = sys.argv[1]
    ee.EXPLORER.update(tc.EXPLORER)
    ee.FORK.update(tc.FORK)
    ee.CHAIN = chain
    out = ROOT / f"data/test3_exploits_{chain}.jsonl"
    src = ROOT / "data/raw/DeFiHackLabs"
    files = sorted(p for p in src.rglob("*.sol") if "RPCS_alive" not in p.name)
    ee.TX = re.compile(ee.EXPLORER[chain] + r"/tx/(0x[0-9a-fA-F]{64})")
    frozen = {p: r for p in files if (r := ee.parse(p))}
    ee.TX = HASH
    recs = []
    for p in files:
        if p in frozen:
            recs.append({**frozen[p], "extractor": "frozen"})
            continue
        r = ee.parse(p)
        if r is None:
            fork = ee.FORK[chain]
            text = p.read_text(errors="ignore")
            if f'createSelectFork("{fork}"' not in text and f"createSelectFork('{fork}'" not in text:
                continue
            txs = continuation_txs(p)
            if not txs:
                continue
            ee.TX = re.compile(r"(?!)")  # parse() only for the other fields
            r = ee.parse(p) or None
            ee.TX = HASH
            if r is None:  # parse() needs an attack-tx hash on the line; rebuild fields directly
                header = "\n".join(text.splitlines()[:60])
                r = {"name": p.stem, "chain": chain, "file": str(p)}
                for key, rx in ee.FIELDS.items():
                    m = rx.search(header)
                    if m:
                        r[key] = m.group(1).strip() if key == "lost" else [a.lower() for a in ee.ADDR.findall(m.group(1))]
                m = re.search(r"createSelectFork\(\s*[\"']" + fork + r"[\"']\s*,\s*([0-9_]+)", text)
                if m:
                    r["fork_block"] = int(m.group(1).replace("_", ""))
                month = p.parent.name
                r["month"] = month if re.fullmatch(r"\d{4}-\d{2}", month) else None
            r["attack_txs"] = txs
        recs.append({**r, "extractor": "broad"})
    seen, unique = set(), []
    for r in recs:
        if r["attack_txs"][0] not in seen:
            seen.add(r["attack_txs"][0])
            unique.append(r)
    out.write_text("".join(json.dumps(r) + "\n" for r in unique))
    nf = sum(r["extractor"] == "frozen" for r in unique)
    print(f"{chain}: {len(unique)} incidents ({nf} frozen extractor, {len(unique) - nf} broad); "
          f"with victim: {sum(1 for r in unique if r.get('victim'))}")
