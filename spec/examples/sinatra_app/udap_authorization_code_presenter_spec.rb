require 'spec_helper'

require_relative '../../../examples/sinatra_app/models/fhir_server'
require_relative '../../../examples/sinatra_app/models/udap_client_credentials'
require_relative '../../../examples/sinatra_app/models/udap_trust_policy'
require_relative '../../../examples/sinatra_app/models/udap_authorization_code_presenter'

RSpec.describe UdapAuthorizationCodePresenter do
  let(:server) do
    FhirServer.new(
      id: 'udap-server',
      name: 'UDAP Server',
      base_url: 'https://fhir.example.com',
      protocols: ['udap'],
      scopes: %w[openid patient/Patient.rs],
      udap_client_id: 'stored-client',
      udap_community: 'https://community.example.org/udap'
    )
  end
  let(:credentials) { instance_double(UdapClientCredentials, configured?: true) }
  let(:trust_policy) { instance_double(UdapTrustPolicy, development_mode?: false) }

  def build_presenter(params: {}, **attrs)
    described_class.new(server:, params:, credentials:, trust_policy:,
                        redirect_uri: 'http://localhost:4567/callback', **attrs)
  end

  describe 'form defaults' do
    it 'uses the stored UDAP registration context when no params are supplied' do
      presenter = build_presenter

      expect(presenter.client_id).to eq('stored-client')
      expect(presenter.community).to eq('https://community.example.org/udap')
      expect(presenter.scope).to eq('openid patient/Patient.rs')
      expect(presenter.redirect_uri).to eq('http://localhost:4567/callback')
    end

    it 'prefers the stored registration scope and splits scopes on commas and whitespace' do
      server.udap_scope = 'openid, fhirUser  user/*.rs'

      expect(build_presenter.scopes).to eq(%w[openid fhirUser user/*.rs])
    end

    it 'keeps submitted blank values instead of falling back to stored values' do
      presenter = build_presenter(params: { 'client_id' => ' ', 'community' => '', 'scope' => '' })

      expect([presenter.client_id, presenter.community, presenter.scopes]).to eq(['', '', []])
    end
  end

  describe 'token display' do
    let(:token_response) do
      {
        'access_token' => 'abcd-access-token-secret-middle-wxyz',
        'refresh_token' => 'refresh-secret',
        'id_token' => 'id-token-secret',
        'token_type' => 'Bearer',
        'expires_in' => 300,
        'scope' => 'openid patient/Patient.rs',
        'patient' => '123',
        'unexpected' => 'value'
      }
    end

    it 'masks the access token and filters refresh, ID, and unknown fields' do
      presenter = build_presenter(token_response:)

      expect(presenter.masked_access_token).to eq('abcd...wxyz (36 characters)')
      expect(presenter.safe_token_response).to eq(
        'access_token' => 'abcd...wxyz (36 characters)',
        'refresh_token' => '[FILTERED]',
        'id_token' => '[FILTERED]',
        'token_type' => 'Bearer',
        'expires_in' => 300,
        'scope' => 'openid patient/Patient.rs',
        'patient' => '123',
        'unexpected' => '[FILTERED]'
      )
      expect(presenter.refresh_token_issued?).to be(true)
      expect(presenter.granted_scopes).to eq(%w[openid patient/Patient.rs])
    end

    it 'reports short or non-String access tokens without revealing them' do
      expect(build_presenter(token_response: { 'access_token' => 'short' }).masked_access_token)
        .to eq('[FILTERED] (5 characters)')
      expect(build_presenter(token_response: { 'access_token' => 123 }).masked_access_token).to eq('[FILTERED]')
    end

    it 'reports no refresh token when none is issued' do
      expect(build_presenter(token_response: { 'access_token' => 'x' }).refresh_token_issued?).to be(false)
    end
  end

  describe 'errors' do
    it 'labels Safire errors and exposes the OAuth error code' do
      presenter = build_presenter(error: Safire::Errors::TokenError.new(status: 400, error_code: 'invalid_grant'))

      expect(presenter.error_label).to eq('Token error')
      expect(presenter.oauth_error_code).to eq('invalid_grant')
    end

    it 'surfaces trust policy configuration errors' do
      allow(trust_policy).to receive(:development_mode?).and_raise(
        Safire::Errors::ConfigurationError.new(invalid_attribute: :UDAP_VERIFY_CHAIN, invalid_value: 'x',
                                               valid_values: %w[true false])
      )
      presenter = build_presenter

      expect(presenter.development_trust_mode?).to be(true)
      expect(presenter.error_label).to eq('Configuration error')
    end

    it 'keeps the authorization response error separately from Safire errors' do
      presenter = build_presenter(authorization_error: { error: 'access_denied', error_description: nil })

      expect(presenter.authorization_error).to eq(error: 'access_denied', error_description: nil)
      expect(presenter.display_error).to be_nil
      expect(presenter.invalid_idp?).to be(false)
    end

    it 'recognizes the Tiered OAuth invalid_idp authorization error' do
      presenter = build_presenter(authorization_error: { error: 'invalid_idp', error_description: nil })

      expect(presenter.invalid_idp?).to be(true)
      expect(build_presenter.invalid_idp?).to be(false)
    end
  end

  describe 'Tiered OAuth preferred IdP' do
    it 'is blank by default so no Tiered OAuth is requested' do
      presenter = build_presenter

      expect(presenter.idp).to eq('')
      expect(presenter.tiered_oauth_idp).to be_nil
    end

    it 'treats a whitespace-only IdP as no Tiered OAuth' do
      expect(build_presenter(params: { 'idp' => "  \t" }).tiered_oauth_idp).to be_nil
    end

    it 'strips surrounding whitespace from a submitted IdP' do
      presenter = build_presenter(params: { idp: ' https://idp.example.com/oidc ' })

      expect(presenter.tiered_oauth_idp).to eq('https://idp.example.com/oidc')
    end
  end
end
