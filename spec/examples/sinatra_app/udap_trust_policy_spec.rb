require 'spec_helper'
require 'openssl'

require_relative '../../../examples/sinatra_app/models/udap_trust_policy'

RSpec.describe UdapTrustPolicy do
  let(:key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:cert) { build_cert(key) }
  let(:crl) { build_crl(cert, key) }

  def build_cert(key)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = OpenSSL::X509::Name.parse('/CN=Demo UDAP Anchor')
    cert.issuer = cert.subject
    cert.public_key = key.public_key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 86_400
    cert.sign(key, OpenSSL::Digest.new('SHA256'))
    cert
  end

  def build_crl(cert, key)
    crl = OpenSSL::X509::CRL.new
    crl.version = 1
    crl.issuer = cert.subject
    crl.last_update = Time.now - 60
    crl.next_update = Time.now + 86_400
    crl.sign(key, OpenSSL::Digest.new('SHA256'))
    crl
  end

  it 'uses development mode when no trust material is configured' do
    policy = described_class.new({})

    expect(policy.server_metadata_kwargs).to eq(
      trusted_anchors: [],
      crls: [],
      verify_chain: false
    )
    expect(policy).to be_development_mode
    expect(policy.chain_verification_disabled_reason).to eq(:missing_trust_material)
  end

  it 'enables chain verification when trust anchors and CRLs are configured' do
    policy = described_class.new(
      'UDAP_TRUST_ANCHORS_PEM' => cert.to_pem,
      'UDAP_CRLS_PEM' => crl.to_pem
    )

    expect(policy.server_metadata_kwargs[:trusted_anchors]).to contain_exactly(be_a(OpenSSL::X509::Certificate))
    expect(policy.server_metadata_kwargs[:crls]).to contain_exactly(be_a(OpenSSL::X509::CRL))
    expect(policy.server_metadata_kwargs[:trusted_anchors]).to be_frozen
    expect(policy.server_metadata_kwargs[:crls]).to be_frozen
    expect(policy.server_metadata_kwargs[:verify_chain]).to be(true)
    expect(policy).not_to be_development_mode
    expect(policy.chain_verification_disabled_reason).to be_nil
  end

  [
    ['trust anchors without CRLs', { 'UDAP_TRUST_ANCHORS_PEM' => :cert }],
    ['CRLs without trust anchors', { 'UDAP_CRLS_PEM' => :crl }]
  ].each do |label, env_template|
    it "stays in development mode when configured with #{label}" do
      env = env_template.transform_values { |value| value == :cert ? cert.to_pem : crl.to_pem }
      policy = described_class.new(env)

      expect(policy.server_metadata_kwargs[:verify_chain]).to be(false)
      expect(policy).to be_development_mode
      expect(policy.chain_verification_disabled_reason).to eq(:missing_trust_material)
    end
  end

  it 'honors an explicit verify_chain=false override' do
    policy = described_class.new(
      'UDAP_TRUST_ANCHORS_PEM' => cert.to_pem,
      'UDAP_CRLS_PEM' => crl.to_pem,
      'UDAP_VERIFY_CHAIN' => 'false'
    )

    expect(policy.server_metadata_kwargs[:verify_chain]).to be(false)
    expect(policy.chain_verification_disabled_reason).to eq(:explicit_override)
  end

  it 'honors explicit true and false boolean values' do
    expect(described_class.new('UDAP_VERIFY_CHAIN' => 'yes').server_metadata_kwargs[:verify_chain]).to be(true)
    expect(described_class.new('UDAP_VERIFY_CHAIN' => '0').server_metadata_kwargs[:verify_chain]).to be(false)
  end

  it 'raises ConfigurationError for invalid verify_chain values' do
    policy = described_class.new('UDAP_VERIFY_CHAIN' => 'treu')

    expect { policy.server_metadata_kwargs }
      .to raise_error(Safire::Errors::ConfigurationError, /UDAP_VERIFY_CHAIN/)
  end

  it 'raises CertificateError for malformed trust anchor PEM without leaking PEM content' do
    malformed_cert = <<~PEM
      -----BEGIN CERTIFICATE-----
      not a certificate
      -----END CERTIFICATE-----
    PEM
    policy = described_class.new('UDAP_TRUST_ANCHORS_PEM' => malformed_cert)

    expect { policy.server_metadata_kwargs }
      .to raise_error(Safire::Errors::CertificateError) { |error|
        expect(error.message).to include('UDAP_TRUST_ANCHORS_PEM')
        expect(error.message).not_to include('not a certificate')
      }
  end

  it 'raises CertificateError for malformed CRL PEM' do
    policy = described_class.new('UDAP_CRLS_PEM' => 'not pem')

    expect { policy.server_metadata_kwargs }
      .to raise_error(Safire::Errors::CertificateError, /UDAP_CRLS_PEM/)
  end
end
