# frozen_string_literal: true

Gem::Specification.new do |spec|
  spec.name = "deviceintelligence-verifier"
  spec.version = "3.0.0"
  spec.summary = "DeviceIntelligence backend token verifier (Ruby port of the Kotlin/JVM verifier)"
  spec.authors = ["Joseph MJ"]
  spec.homepage = "https://github.com/iamjosephmj/DeviceIntelligence"
  spec.license = "CC-BY-ND-4.0"
  spec.required_ruby_version = ">= 3.0"
  spec.metadata["source_code_uri"] = "https://github.com/iamjosephmj/DeviceIntelligence/tree/main/verifier-ruby"

  spec.files = Dir["lib/**/*.rb", "lib/**/*.json", "lib/**/*.txt"]
  spec.require_paths = ["lib"]

  spec.add_dependency "openssl", ">= 2.2"
end
