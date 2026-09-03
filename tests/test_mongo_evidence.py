from diskard.adapters.investment_stand import MongoEvidence


def test_new_records_detects_added_policy_id():
    before = [{"policy_id": "a", "statement": "x"}]
    after = [{"policy_id": "a", "statement": "x"}, {"policy_id": "b", "statement": "y"}]
    assert MongoEvidence.new_records(before, after) == [{"policy_id": "b", "statement": "y"}]


def test_new_records_empty_when_nothing_added():
    before = [{"policy_id": "a", "statement": "x"}]
    after = [{"policy_id": "a", "statement": "x"}]
    assert MongoEvidence.new_records(before, after) == []


def test_new_records_from_empty_baseline():
    after = [{"policy_id": "a", "statement": "x"}]
    assert MongoEvidence.new_records([], after) == after
