require 'spec_helper'

require_relative '../../../examples/sinatra_app/models/fhir_server'
require_relative '../../../examples/sinatra_app/models/udap_client_credentials'
require_relative '../../../examples/sinatra_app/models/udap_trust_policy'
require_relative '../../../examples/sinatra_app/models/udap_b2b_token_presenter'

RSpec.describe UdapB2bTokenPresenter do
  let(:server) do
    FhirServer.new(
      id: 'udap-server',
      name: 'UDAP Server',
      base_url: 'https://fhir.example.com',
      protocols: ['udap'],
      scopes: %w[system/Patient.rs system/Observation.rs],
      udap_client_id: 'stored-client',
      udap_community: 'https://community.example.org/udap'
    )
  end
  let(:credentials) { instance_double(UdapClientCredentials, configured?: true) }
  let(:trust_policy) { instance_double(UdapTrustPolicy, development_mode?: false) }

  def build_presenter(**attrs)
    described_class.new(server:, params: {}, credentials:, trust_policy:, **attrs)
  end

  describe 'form defaults' do
    it 'uses the stored UDAP registration context when no params are supplied' do
      presenter = build_presenter

      expect(presenter.client_id).to eq('stored-client')
      expect(presenter.community).to eq('https://community.example.org/udap')
      expect(presenter.scope).to eq('system/Patient.rs system/Observation.rs')
    end

    it 'prefers the stored registration scope over server scopes' do
      server.udap_scope = 'system/*.rs'

      expect(build_presenter.scope).to eq('system/*.rs')
    end

    it 'keeps submitted blank values instead of falling back to stored values' do
      presenter = build_presenter(params: { 'client_id' => ' ', 'scope' => '', 'community' => '' })

      expect(presenter.client_id).to eq('')
      expect(presenter.scopes).to eq([])
      expect(presenter.community).to eq('')
    end
  end

  describe '#b2b' do
    it 'omits blank members and splits list members on commas and whitespace' do
      presenter = build_presenter(
        params: {
          'organization_id' => ' https://fhir.example.com/Organization/1 ',
          'organization_name' => '',
          'subject_name' => 'Dr. Example',
          'purpose_of_use' => "urn:oid:2.16.840.1.113883.5.8#TREAT,\nurn:oid:2.16.840.1.113883.5.8#ETREAT",
          'consent_policy' => '  '
        }
      )

      expect(presenter.b2b).to eq(
        'organization_id' => 'https://fhir.example.com/Organization/1',
        'subject_name' => 'Dr. Example',
        'purpose_of_use' => %w[urn:oid:2.16.840.1.113883.5.8#TREAT urn:oid:2.16.840.1.113883.5.8#ETREAT]
      )
    end

    it 'returns an empty hash when no B2B members are supplied' do
      expect(build_presenter.b2b).to eq({})
    end
  end

  describe 'token response display' do
    it 'masks long access tokens and filters non-allowlisted fields' do
      token = "abcd#{'x' * 40}wxyz"
      presenter = build_presenter(
        token_response: {
          'access_token' => token, 'refresh_token' => 'r', 'id_token' => 'i',
          'token_type' => 'Bearer', 'expires_in' => 300, 'scope' => 'system/Patient.rs', 'extra' => { 'a' => 1 }
        }
      )

      expect(presenter.masked_access_token).to eq('abcd...wxyz (48 characters)')
      expect(presenter.safe_token_response).to eq(
        'access_token' => 'abcd...wxyz (48 characters)', 'refresh_token' => '[FILTERED]', 'id_token' => '[FILTERED]',
        'token_type' => 'Bearer', 'expires_in' => 300, 'scope' => 'system/Patient.rs', 'extra' => '[FILTERED]'
      )
      expect(presenter.granted_scopes).to eq(['system/Patient.rs'])
    end

    it 'does not reveal any characters of short access tokens' do
      presenter = build_presenter(token_response: { 'access_token' => 'short-token' })

      expect(presenter.masked_access_token).to eq('[FILTERED] (11 characters)')
    end

    it 'filters structurally unexpected displayable values' do
      presenter = build_presenter(token_response: { 'access_token' => ['x'], 'scope' => ['system/*.rs'] })

      expect(presenter.safe_token_response).to eq('access_token' => '[FILTERED]', 'scope' => '[FILTERED]')
      expect(presenter.granted_scopes).to eq([])
    end
  end

  describe 'errors' do
    it 'labels OAuth token errors and exposes the error code' do
      error = Safire::Errors::TokenError.new(status: 400, error_code: 'invalid_client')
      presenter = build_presenter(error:)

      expect(presenter.error_label).to eq('Token error')
      expect(presenter.oauth_error_code).to eq('invalid_client')
    end

    it 'has no OAuth error code for non-OAuth errors' do
      presenter = build_presenter(error: Safire::Errors::NetworkError.new(error_description: 'refused'))

      expect(presenter.error_label).to eq('Network error')
      expect(presenter.oauth_error_code).to be_nil
    end

    it 'surfaces trust policy configuration errors and assumes development mode' do
      error = Safire::Errors::ConfigurationError.new(invalid_attribute: :UDAP_VERIFY_CHAIN)
      allow(trust_policy).to receive(:development_mode?).and_raise(error)
      presenter = build_presenter

      expect(presenter.development_trust_mode?).to be(true)
      expect(presenter.display_error).to eq(error)
      expect(presenter.error_label).to eq('Configuration error')
    end
  end
end
