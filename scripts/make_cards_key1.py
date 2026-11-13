"""Run make_cards with the second Alchemy key (separate rate-limit budget). Same data, same frozen card code:
only the RPC credential used by CardBuilder.for_chain changes (oracle/ is untouched)."""
import sys

import oracle.card as card

try:  # runtime config for extra chains (avalanche, linea, blast, ...) collected for test v4
    import test4_chains
    test4_chains.install()
except Exception:  # noqa: BLE001
    pass
from oracle.sources import Alchemy, Etherscan, Prices

card.CardBuilder.for_chain = classmethod(lambda cls, chain: cls(Alchemy(chain, key=1), Etherscan(chain), Prices(chain), chain))

import make_cards  # noqa: E402

if __name__ == "__main__":
    sys.exit(make_cards.main())
