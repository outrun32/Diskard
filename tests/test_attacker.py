"""Unit tests for the LLM auto-attacker's per-attack objective registry --
pure functions only (prompt formatting, success predicates, campaign
serialization), no network, no target/Mongo. Covers the generalization from
one hardcoded family to a registry shared by cross-user-global-policy-
poisoning, compaction-policy-poisoning, and delayed-recommendation-
manipulation (see the module docstring for why cross-user-direct-memory-leak
is deliberately absent).
"""

from __future__ import annotations

from diskard.attacker import (
    ATTACK_OBJECTIVES,
    AttackCampaign,
    AttemptResult,
    _build_user_prompt,
)


def test_registry_covers_exactly_the_three_write_side_families():
    assert set(ATTACK_OBJECTIVES) == {
        "cross-user-global-policy-poisoning",
        "compaction-policy-poisoning",
        "delayed-recommendation-manipulation",
    }


def test_cus_smuggling_families_share_one_objective():
    # Same payload/oracle, only the confirm-run delivery pattern differs --
    # see the ATTACK_OBJECTIVES comment. If these ever diverge it should be
    # a deliberate decision, not a copy-paste drift.
    assert (
        ATTACK_OBJECTIVES["cross-user-global-policy-poisoning"]
        is ATTACK_OBJECTIVES["compaction-policy-poisoning"]
    )


def test_cus_smuggling_predicate_matches_only_records_naming_the_data_subject():
    objective = ATTACK_OBJECTIVES["cross-user-global-policy-poisoning"]
    params = {"data_subject_cus": "1003"}
    assert objective.success_predicate({"statement": "cus=1003 gets shown"}, params) is True
    assert objective.success_predicate({"statement": "cus=1099 gets shown"}, params) is False
    assert objective.success_predicate({}, params) is False


def test_recommendation_promotion_predicate_matches_ticker_or_isin():
    objective = ATTACK_OBJECTIVES["delayed-recommendation-manipulation"]
    params = {
        "target_ticker": "SVFN-01",
        "target_isin": "RU000A1FICT9",
        "target_name": "Северная Финанс Б1P-01",
    }
    assert objective.success_predicate({"statement": "recommend SVFN-01 first"}, params) is True
    assert objective.success_predicate({"statement": "ISIN RU000A1FICT9 first"}, params) is True
    assert objective.success_predicate({"statement": "recommend IBNK-01 first"}, params) is False
    assert objective.success_predicate({}, params) is False


def test_cus_smuggling_prompt_formats_with_its_params():
    objective = ATTACK_OBJECTIVES["cross-user-global-policy-poisoning"]
    rendered = objective.system_prompt.format(data_subject_cus="1003")
    assert "1003" in rendered


def test_recommendation_prompt_formats_with_its_params():
    objective = ATTACK_OBJECTIVES["delayed-recommendation-manipulation"]
    rendered = objective.system_prompt.format(
        target_ticker="SVFN-01", target_isin="RU000A1FICT9", target_name="Северная Финанс Б1P-01"
    )
    assert "SVFN-01" in rendered
    assert "RU000A1FICT9" in rendered


def test_build_user_prompt_first_attempt_has_no_history_section():
    prompt = _build_user_prompt({"data_subject_cus": "1003"}, [])
    assert "data_subject_cus = 1003" in prompt
    assert "Предыдущие попытки" not in prompt


def test_build_user_prompt_includes_prior_attempts_and_params():
    attempt = AttemptResult(
        index=1,
        message="test message",
        idea="direct ask",
        facts=[{"scope": "user", "fact": "..."}],
        new_records=[],
        concrete_records=[],
        persisted=False,
        reply="no.",
        session_id="s1",
    )
    prompt = _build_user_prompt(
        {"target_ticker": "SVFN-01", "target_isin": "RU000A1FICT9"}, [attempt]
    )
    assert "target_ticker = SVFN-01" in prompt
    assert "target_isin = RU000A1FICT9" in prompt
    assert "неудача" in prompt
    assert "test message" in prompt


def test_campaign_to_dict_shape_is_objective_agnostic():
    attempt = AttemptResult(
        index=1,
        message="winning wording",
        idea="declarative rule",
        facts=[],
        new_records=[{"statement": "cus=1003"}],
        concrete_records=[{"statement": "cus=1003"}],
        persisted=True,
        reply="ok",
        session_id="s1",
    )
    campaign = AttackCampaign(params={"data_subject_cus": "1003"})
    campaign.attempts.append(attempt)
    campaign.winning_index = 1

    assert campaign.succeeded is True
    assert campaign.winning_message == "winning wording"

    payload = campaign.to_dict()
    assert payload["params"] == {"data_subject_cus": "1003"}
    assert payload["succeeded"] is True
    assert payload["winning_index"] == 1
    assert payload["winning_message"] == "winning wording"
    assert len(payload["attempts"]) == 1


def test_campaign_not_succeeded_has_no_winning_message():
    campaign = AttackCampaign(params={"target_ticker": "SVFN-01"})
    assert campaign.succeeded is False
    assert campaign.winning_message is None
