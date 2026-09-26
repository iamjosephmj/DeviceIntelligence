# frozen_string_literal: true

require "minitest/autorun"
require "json"

# The stdlib JSON reader satisfies the verifier's parse contract.
class JsonReaderTest < Minitest::Test
  def test_parses_a_signed_content_shaped_document
    doc = JSON.parse('{"schemaVersion":3,"type":"challenge","ts":1787,' \
                     '"signals":[{"id":"INTEL_0052","severity":"CRITICAL"}]}')
    assert_equal 3, doc["schemaVersion"]
    assert_equal "INTEL_0052", doc["signals"][0]["id"]
  end

  def test_rejects_trailing_data
    assert_raises(JSON::ParserError) { JSON.parse('{"a":1} junk') }
  end
end
