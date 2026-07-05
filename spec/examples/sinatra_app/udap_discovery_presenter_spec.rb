require 'spec_helper'

require_relative '../../../examples/sinatra_app/models/udap_trust_policy'
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

  def build_presenter(metadata_valid: true, verify_chain: false)
    described_class.new(
      metadata,
      metadata_valid: metadata_valid,
      trust_policy: instance_double(UdapTrustPolicy, verify_chain?: verify_chain)
    )
  end

  describe '#metadata_fields' do
    it 'returns every STU2 UDAP metadata field in entity order' do
      presenter = described_class.new(
        metadata,
        metadata_valid: true,
        trust_policy: UdapTrustPolicy.new({})
      )

      expect(presenter.metadata_fields.pluck(:key)).to eq(Safire::Protocols::UdapMetadata::ATTRIBUTES)
    end
  end

  describe '#profile_checks' do
    it 'reports profile-only checks separately from capability checks' do
      presenter = described_class.new(
        metadata,
        metadata_valid: true,
        trust_policy: UdapTrustPolicy.new({})
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
        trust_policy: UdapTrustPolicy.new({})
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
        trust_policy: UdapTrustPolicy.new({})
      )

      expect(presenter).to be_trust_warning
    end

    it 'explains missing trust material when chain verification is disabled by default' do
      presenter = described_class.new(
        metadata,
        metadata_valid: true,
        trust_policy: UdapTrustPolicy.new({})
      )

      expect(presenter.trust_warning_reason).to include('complete UDAP trust anchors and CRLs are not configured')
    end

    it 'explains explicit override when chain verification is disabled by configuration' do
      policy = UdapTrustPolicy.new('UDAP_VERIFY_CHAIN' => 'false')
      presenter = described_class.new(
        metadata,
        metadata_valid: true,
        trust_policy: policy
      )

      expect(presenter.trust_warning_reason).to include('UDAP_VERIFY_CHAIN explicitly disables')
    end
  end

  describe 'status display helpers' do
    it 'summarizes structural metadata validation status' do
      conformant = build_presenter
      non_conformant = build_presenter(metadata_valid: false)

      expect(conformant.structural_status).to eq('Conformant')
      expect(non_conformant.structural_status).to eq('Non-conformant')
    end

    it 'summarizes signed metadata validation status by trust mode' do
      chain_verified = build_presenter(verify_chain: true)
      dev_verified = build_presenter

      expect(chain_verified.signed_metadata_status).to eq('Validated with chain and revocation checks')
      expect(dev_verified.signed_metadata_status).to eq('Validated without chain verification')
    end

    it 'formats boolean status text and badge classes' do
      presenter = described_class.new(
        metadata,
        metadata_valid: true,
        trust_policy: UdapTrustPolicy.new({})
      )

      expect(presenter.status_text(true)).to eq('Yes')
      expect(presenter.status_text(false)).to eq('No')
      expect(presenter.badge_class(true)).to eq('badge-added')
      expect(presenter.badge_class(false)).to eq('badge-info')
    end
  end
end
