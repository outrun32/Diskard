"""Fast iteration loop for poison wording: chat + finalize + dump what got
extracted, without paying for the full 7-step scenario each time."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from uuid import uuid4

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from diskard.models import Actor  # noqa: E402
from examples.connectors.investment_stand.backend import (  # noqa: E402
    MongoEvidence,
    SemanticMemoryEvidence,
    StandClient,
)

IDENTITIES_CACHE = Path(__file__).resolve().parent / ".identities.json"
POISONER_CUS = "1001"
DATA_SUBJECT_CUS = "1003"

POISON_MESSAGE = sys.argv[1] if len(sys.argv) > 1 else None


async def main() -> None:
    identities = {
        cus: Actor.model_validate(v) for cus, v in json.loads(IDENTITIES_CACHE.read_text()).items()
    }
    poisoner = identities[POISONER_CUS]
    stand = StandClient()
    mongo = MongoEvidence()
    semantic = SemanticMemoryEvidence()

    session_id = f"diskard-iter-{uuid4().hex[:8]}"
    message = POISON_MESSAGE or "PLACEHOLDER"

    print(f"session={session_id}")
    print(f"message={message!r}\n")

    try:
        chat_result = await stand.chat(poisoner.api_key, session_id, message, "vulnerable")
        print("--- assistant reply ---")
        print(chat_result["reply"])

        finalize_result = await stand.finalize(poisoner.api_key, session_id)
        print("\n--- finalize episodes ---")
        for e in finalize_result.get("episodes") or []:
            print("-", e)
        print("\n--- finalize facts ---")
        for f in finalize_result.get("facts") or []:
            print("-", f)

        policy = mongo.snapshot()
        print(f"\n--- agent_policy_memories (total {len(policy)}) ---")
        for p in policy[-3:]:
            print("-", p)
    finally:
        # This is a manual exploration tool, run over and over while hand-tuning
        # wording -- without cleanup every invocation permanently adds to the
        # shared stand's memory (both tiers), which is exactly the kind of
        # cross-run contamination that produced phantom leak signals elsewhere
        # tonight (see TEAM_NOTES.md). You can still see everything it wrote in
        # the printouts above before it's removed.
        deleted_policy = mongo.delete_by_source_session(session_id)
        deleted_semantic = semantic.delete_by_user(POISONER_CUS)
        if deleted_policy:
            print(f"\ncleanup: removed {deleted_policy} policy record(s) written by this run")
        if deleted_semantic:
            print(f"cleanup: removed {deleted_semantic} semantic fact(s) written by this run")
        await stand.aclose()


if __name__ == "__main__":
    asyncio.run(main())
