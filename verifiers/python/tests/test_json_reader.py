"""The stdlib JSON reader satisfies the verifier's parse contract."""
import json


def test_parses_a_signed_content_shaped_document():
    doc = json.loads('{"schemaVersion":3,"type":"challenge","ts":1787,'
                     '"signals":[{"id":"INTEL_0052","severity":"CRITICAL"}]}')
    assert doc["schemaVersion"] == 3
    assert doc["signals"][0]["id"] == "INTEL_0052"


def test_rejects_trailing_data():
    import pytest
    with pytest.raises(ValueError):
        json.loads('{"a":1} junk')
