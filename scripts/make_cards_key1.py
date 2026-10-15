"""Run make_cards with the second Alchemy key (separate rate-limit budget). Same data, same frozen card code:
only the RPC credential used by CardBuilder.for_chain changes (oracle/ is untouched)."""
import sys

import oracle.card as card
from oracle.sources import Alchemy, Etherscan, Prices

card.CardBuilder.for_chain = classmethod(lambda cls, chain: cls(Alchemy(chain, key=1), Etherscan(chain), Prices(chain), chain))

import make_cards  # noqa: E402

if __name__ == "__main__":
    sys.exit(make_cards.main())
