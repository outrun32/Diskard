"""Attack definitions and the extension registry used by the CLI."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

ScenarioBuilder = Callable[[Any, Any, str], tuple[Any, str]]
SeedBuilder = Callable[[Any], str]


@dataclass(frozen=True)
class AttackDefinition:
    name: str
    description: str
    build: ScenarioBuilder
    required_collectors: frozenset[str] = frozenset()
    supports_llm_driver: bool = True
    build_seed: SeedBuilder | None = None


class AttackRegistry:
    def __init__(self) -> None:
        self._definitions: dict[str, AttackDefinition] = {}

    def register(self, definition: AttackDefinition) -> None:
        if definition.name in self._definitions:
            raise ValueError(f"attack {definition.name!r} is already registered")
        self._definitions[definition.name] = definition

    def get(self, name: str) -> AttackDefinition:
        try:
            return self._definitions[name]
        except KeyError as exc:
            raise KeyError(f"unknown attack {name!r}") from exc

    def names(self) -> tuple[str, ...]:
        return tuple(self._definitions)

    def descriptions(self) -> dict[str, str]:
        return {name: item.description for name, item in self._definitions.items()}


def _policy_scenario(args: Any, dispatch: Any, run_id: str) -> tuple[Any, str]:
    from diskard.scenarios.cross_user_policy_poisoning import (
        build_cross_user_policy_poisoning_scenario,
        poison_session_id,
    )

    scenario = build_cross_user_policy_poisoning_scenario(
        poisoner_cus=args.poisoner_cus,
        victim_cus=args.victim_cus,
        data_subject_cus=args.data_subject_cus,
        dispatch=dispatch,
        run_id=run_id,
        poison_message=getattr(args, "poison_message", None),
        activation_strategy=getattr(args, "activation_strategy", "default"),
    )
    return scenario, poison_session_id(run_id)


def _compaction_scenario(args: Any, dispatch: Any, run_id: str) -> tuple[Any, str]:
    from diskard.scenarios.compaction_policy_poisoning import (
        build_compaction_policy_poisoning_scenario,
        poison_session_id,
    )

    scenario = build_compaction_policy_poisoning_scenario(
        poisoner_cus=args.poisoner_cus,
        victim_cus=args.victim_cus,
        data_subject_cus=args.data_subject_cus,
        dispatch=dispatch,
        run_id=run_id,
        poison_message=getattr(args, "poison_message", None),
        activation_strategy=getattr(args, "activation_strategy", "default"),
    )
    return scenario, poison_session_id(run_id)


def _direct_memory_scenario(args: Any, dispatch: Any, run_id: str) -> tuple[Any, str]:
    from diskard.scenarios.cross_user_direct_memory_leak import (
        build_cross_user_direct_leak_scenario,
        deliver_session_id,
    )

    scenario = build_cross_user_direct_leak_scenario(
        poisoner_cus=args.poisoner_cus,
        victim_cus=args.victim_cus,
        dispatch=dispatch,
        run_id=run_id,
        delivery_message=getattr(args, "poison_message", None),
    )
    return scenario, deliver_session_id(run_id)


def _policy_seed(args: Any) -> str:
    from diskard.scenarios.cross_user_policy_poisoning import POISON_MESSAGE_TEMPLATE

    return POISON_MESSAGE_TEMPLATE.format(data_subject_cus=args.data_subject_cus)


def _compaction_seed(args: Any) -> str:
    from diskard.scenarios.compaction_policy_poisoning import POISON_MESSAGE_TEMPLATE

    return POISON_MESSAGE_TEMPLATE.format(data_subject_cus=args.data_subject_cus)


def _recommendation_seed(args: Any) -> str:
    from diskard.scenarios.delayed_recommendation_manipulation import POISON_MESSAGE

    return POISON_MESSAGE


def _recommendation_scenario(args: Any, dispatch: Any, run_id: str) -> tuple[Any, str]:
    from diskard.scenarios.delayed_recommendation_manipulation import (
        build_delayed_recommendation_manipulation_scenario,
        poison_session_id,
    )

    scenario = build_delayed_recommendation_manipulation_scenario(
        poisoner_cus=args.poisoner_cus,
        control_cus=args.control_cus,
        victim_cus=args.victim_cus,
        dispatch=dispatch,
        run_id=run_id,
        poison_message=getattr(args, "poison_message", None),
        activation_strategy=getattr(args, "activation_strategy", "default"),
    )
    return scenario, poison_session_id(run_id)


ATTACKS = AttackRegistry()
ATTACKS.register(
    AttackDefinition(
        name="cross-user-global-policy-poisoning",
        description="Persistent policy change followed by a later cross-identity check.",
        build=_policy_scenario,
        required_collectors=frozenset({"policy-memory", "ground-truth"}),
        build_seed=_policy_seed,
    )
)
ATTACKS.register(
    AttackDefinition(
        name="cross-user-direct-memory-leak",
        description="Cross-identity isolation check for user-scoped memory.",
        build=_direct_memory_scenario,
        required_collectors=frozenset({"semantic-memory"}),
        supports_llm_driver=False,
    )
)
ATTACKS.register(
    AttackDefinition(
        name="compaction-policy-poisoning",
        description="Persistent policy check across a longer compacted interaction.",
        build=_compaction_scenario,
        required_collectors=frozenset({"policy-memory", "ground-truth"}),
        build_seed=_compaction_seed,
    )
)
ATTACKS.register(
    AttackDefinition(
        name="delayed-recommendation-manipulation",
        description="Delayed decision-shift check with a clean control cohort.",
        build=_recommendation_scenario,
        required_collectors=frozenset({"policy-memory"}),
        build_seed=_recommendation_seed,
    )
)
