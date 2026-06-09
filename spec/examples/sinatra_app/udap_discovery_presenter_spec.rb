require 'spec_helper'
require 'openssl'

require_relative '../../../examples/sinatra_app/models/udap_discovery_presenter'

RSpec.describe UdapDiscoveryPresenter do
  let(:base_url) { 'https://fhir.example.com' }
  let(:metadata_hash) do
    {
      'udap_versions_supported' => ['1'],
      'udap_profiles_supported' => %w[udap_dcr udap_authn udap_authz],
      'udap_authorization_extensions_supported' => ['hl7-b2b'],
      'udap_authorization_extensions_required' => ['hl7-b2b'],
      'udap_certifications_supported' => ['https://cert.example.org/udap'],
      'udap_certifications_required' => ['https://cert.example.org/udap'],
      'grant_types_supported' => %w[client_credentials authorization_code],
      'scopes_supported' => %w[openid profile system/*.rs],
      'token_endpoint' => "#{base_url}/token",
      'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
      'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
      'registration_endpoint' => "#{base_url}/register",
      'registration_endpoint_jwt_signing_alg_values_supported' => ['RS256'],
      'authorization_endpoint' => "#{base_url}/authorize",
      'signed_metadata' => 'header.payload.signature'
    }
  end
  let(:metadata) { Safire::Protocols::UdapMetadata.new(metadata_hash) }

  describe '#metadata_fields' do
    it 'returns every STU2 UDAP metadata field in entity order' do
      presenter = described_class.new(
        metadata,
        metadata_valid: true,
        signed_metadata_valid: true,
        trust_policy: described_class::TrustPolicy.new({})
      )

      expect(presenter.metadata_fields.pluck(:key)).to eq(Safire::Protocols::UdapMetadata::ATTRIBUTES)
    end
  end

  describe '#profile_checks' do
    it 'reports profile-only checks separately from capability checks' do
      presenter = described_class.new(
        metadata,
        metadata_valid: true,
        signed_metadata_valid: true,
        trust_policy: described_class::TrustPolicy.new({})
      )

      expect(presenter.profile_checks).to include(
        { label: 'Dynamic Client Registration profile', result: true },
        { label: 'JWT Client Authentication profile', result: true }
      )
      expect(presenter.profile_checks.pluck(:label)).not_to include('Dynamic Client Registration capability')
    end
  end

  describe '#capability_checks' do
    it 'reports capability checks that include profile, grant, and endpoint preconditions' do
      presenter = described_class.new(
        metadata,
        metadata_valid: true,
        signed_metadata_valid: true,
        trust_policy: described_class::TrustPolicy.new({})
      )

      expect(presenter.capability_checks).to include(
        { label: 'Dynamic Client Registration capability', result: true },
        { label: 'JWT Client Authentication capability', result: true },
        { label: 'Client Credentials capability', result: true },
        { label: 'Refresh Token grant', result: false }
      )
    end
  end

  describe '#trust_warning?' do
    it 'is true when chain verification is disabled for demo use' do
      presenter = described_class.new(
        metadata,
        metadata_valid: true,
        signed_metadata_valid: true,
        trust_policy: described_class::TrustPolicy.new({})
      )

      expect(presenter).to be_trust_warning
    end
  end

  describe UdapDiscoveryPresenter::TrustPolicy do
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
    end

    it 'enables chain verification when trust anchors and CRLs are configured' do
      policy = described_class.new(
        'UDAP_TRUST_ANCHORS_PEM' => cert.to_pem,
        'UDAP_CRLS_PEM' => crl.to_pem
      )

      expect(policy.server_metadata_kwargs[:trusted_anchors]).to contain_exactly(be_a(OpenSSL::X509::Certificate))
      expect(policy.server_metadata_kwargs[:crls]).to contain_exactly(be_a(OpenSSL::X509::CRL))
      expect(policy.server_metadata_kwargs[:verify_chain]).to be(true)
      expect(policy).not_to be_development_mode
    end

    it 'honors an explicit verify_chain=false override' do
      policy = described_class.new(
        'UDAP_TRUST_ANCHORS_PEM' => cert.to_pem,
        'UDAP_CRLS_PEM' => crl.to_pem,
        'UDAP_VERIFY_CHAIN' => 'false'
      )

      expect(policy.server_metadata_kwargs[:verify_chain]).to be(false)
    end

    it 'raises CertificateError for malformed trust anchor PEM' do
      policy = described_class.new('UDAP_TRUST_ANCHORS_PEM' => 'not pem')

      expect { policy.server_metadata_kwargs }
        .to raise_error(Safire::Errors::CertificateError, /UDAP_TRUST_ANCHORS_PEM/)
    end
  end
end
