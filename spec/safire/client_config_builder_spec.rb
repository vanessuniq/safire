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
             .build

    expect(config).to be_a(Safire::ClientConfig)
    expect(config.certificate_chain).to eq(certificate_chain)
  end
end
