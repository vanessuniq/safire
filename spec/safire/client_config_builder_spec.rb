require 'spec_helper'

RSpec.describe Safire::ClientConfigBuilder do
  subject(:builder) { Safire::ClientConfig.builder }

  let(:certificate_chain) do
    [
      "-----BEGIN CERTIFICATE-----\nleaf-certificate\n-----END CERTIFICATE-----\n"
    ]
  end

  it 'builds a ClientConfig with a certificate chain' do
    config = builder
             .base_url('https://fhir.example.com')
             .certificate_chain(certificate_chain)
             .allow_insecure_localhost(enabled: false)
             .build

    expect(config).to be_a(Safire::ClientConfig)
    expect(config.certificate_chain).to eq(certificate_chain)
    expect(config.allow_insecure_localhost).to be(false)
  end

  it 'can opt into insecure localhost for local development' do
    config = builder
             .base_url('http://localhost:3000/fhir')
             .allow_insecure_localhost
             .build

    expect(config.allow_insecure_localhost).to be(true)
  end
end
