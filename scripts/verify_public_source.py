"""Read-only smoke check of Radar's two added public index collectors."""

import asyncio
import json
import sys

from hunter.discovery import subdomain_center_names, thc_names
from hunter.engine import Control
from hunter.models import ScanOptions, Target
from hunter.network import Network


async def main(domain):
    options = ScanOptions([Target(domain)], timeout=10, interval=0)
    network = Network(options, Control())
    messages = []
    try:
        center = await subdomain_center_names(domain, network, messages.append)
        thc = await thc_names(domain, network, messages.append)
    finally:
        await network.close()
    print(json.dumps({"domain": domain, "subdomain_center_candidates": len(center),
                      "thc_candidates": len(thc), "journal": messages}))


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
