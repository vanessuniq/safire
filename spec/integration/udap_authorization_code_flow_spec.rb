require 'spec_helper'
require_relative '../support/udap_certificate_helpers'

RSpec.describe 'UDAP Authorization Code Flow', type: :integration do
  include UdapCertificateHelpers

  let(:base_url) { 'https://fhir.example.com' }
  let(:well_known_url) { "#{base_url}/.well-known/udap" }
  let(:authorization_endpoint) { "#{base_url}/oauth/authorize" }
  let(:token_endpoint) { "#{base_url}/oauth/token" }
  let(:client_id) { 'udap-client-123' }
  let(:redirect_uri) { 'https://app.example.com/callback' }
  let(:private_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:certificate) { build_udap_certificate(key: private_key, uri_san: 'https://client.example.com/app') }
  let(:config) do
    {
      base_url:,
      client_id:,
      redirect_uri:,
      scopes: %w[openid fhirUser patient/Patient.rs patient/Observation.rs],
      private_key:,
      certificate_chain: [certificate]
    }
  end
  let(:client) { Safire::Client.new(config, protocol: :udap) }
  let(:udap_metadata) do
    {
      'udap_versions_supported' => ['1'],
      'udap_profiles_supported' => %w[udap_dcr udap_authn],
      'udap_authorization_extensions_supported' => [],
      'udap_certifications_supported' => [],
      'grant_types_supported' => %w[authorization_code refresh_token],
      'scopes_supported' => %w[openid fhirUser patient/*.rs],
      'authorization_endpoint' => "#{base_url}/unsigned-authorize",
      'token_endpoint' => "#{base_url}/unsigned-token",
      'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
      'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
      'registration_endpoint' => "#{base_url}/register",
      'registration_endpoint_jwt_signing_alg_values_supported' => ['RS256'],
      'signed_metadata' => 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwcyJ9.c2ln'
    }
  end
  let(:token_requests) { [] }
  let(:issued_codes) { {} }
  let(:warnings) { [] }

  # Simulated authorization server: remembers the code_challenge and
  # redirect_uri bound to each issued code and enforces them at the token
  # endpoint, as RFC 7636 §4.6 and RFC 6749 §4.1.3 require of servers.
  def simulate_user_approval(auth_url)
    params = Addressable::URI.parse(auth_url).query_values
    code = SecureRandom.hex(8)
    issued_codes[code] = params.slice('code_challenge', 'redirect_uri')
    { 'code' => code, 'state' => params['state'] }
  end

  def token_endpoint_response(request)
    form = URI.decode_www_form(request.body).to_h
    token_requests << form
    case form['grant_type']
    when 'authorization_code' then code_exchange_response(form)
    when 'refresh_token' then refresh_response(form)
    end
  end

  def code_exchange_response(form)
    bound = issued_codes.delete(form['code'])
    challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(form['code_verifier'].to_s), padding: false)
    return oauth_error('invalid_grant') unless bound && bound['code_challenge'] == challenge &&
                                               bound['redirect_uri'] == form['redirect_uri']

    json(200, 'access_token' => 'access-1', 'token_type' => 'Bearer', 'expires_in' => 3600,
              'refresh_token' => 'refresh-1', 'scope' => 'openid fhirUser patient/Patient.rs', 'patient' => '123')
  end

  def refresh_response(form)
    return oauth_error('invalid_grant') unless form['refresh_token'] == 'refresh-1'

    json(200, 'access_token' => 'access-2', 'token_type' => 'Bearer', 'expires_in' => 3600,
              'scope' => form['scope'] || 'openid fhirUser patient/Patient.rs')
  end

  def oauth_error(code)
    json(400, 'error' => code)
  end

  def json(status, body)
    { status:, body: body.to_json, headers: { 'Content-Type' => 'application/json' } }
  end

  def decode_assertion(form)
    JWT.decode(form['client_assertion'], certificate.public_key, true, algorithms: ['RS256']).first
  end

  # Application callback handling: STU2 §7.2.1 requires the app to stop when
  # state is missing or does not match.
  def callback_state_valid?(callback, expected_state)
    callback['state'].is_a?(String) && OpenSSL.secure_compare(callback['state'], expected_state)
  end

  before do
    validator = instance_double(
      Safire::Protocols::UdapSignedMetadataValidator,
      signed_endpoint_claims: {
        'token_endpoint' => token_endpoint,
        'registration_endpoint' => "#{base_url}/register",
        'authorization_endpoint' => authorization_endpoint
      }
    )
    allow(Safire::Protocols::UdapSignedMetadataValidator).to receive(:new).and_return(validator)
    allow(Safire.logger).to receive(:warn) { |message| warnings << message }
    stub_request(:get, well_known_url)
      .to_return(status: 200, body: udap_metadata.to_json, headers: { 'Content-Type' => 'application/json' })
    stub_request(:post, token_endpoint).to_return { |request| token_endpoint_response(request) }
  end

  it 'completes authorization, callback state check, code exchange, and refresh' do
    session = client.authorization_url(trusted_anchors: [], verify_chain: false)
    expect(session[:auth_url]).to start_with("#{authorization_endpoint}?")

    callback = simulate_user_approval(session[:auth_url])
    expect(callback_state_valid?(callback, session[:state])).to be(true)

    tokens = client.request_access_token(code: callback['code'], code_verifier: session[:code_verifier],
                                         verify_chain: false)
    expect(tokens).to include('access_token' => 'access-1', 'refresh_token' => 'refresh-1', 'patient' => '123')

    exchange = token_requests.last
    expect(exchange['redirect_uri']).to eq(redirect_uri)
    expect(exchange['udap']).to eq('1')
    expect(decode_assertion(exchange)).to include('iss' => client_id, 'sub' => client_id, 'aud' => token_endpoint)
    expect(decode_assertion(exchange)).not_to have_key('extensions')

    refreshed = client.refresh_token(refresh_token: tokens['refresh_token'], scopes: ['patient/Patient.rs'],
                                     verify_chain: false)
    expect(refreshed).to include('access_token' => 'access-2', 'scope' => 'patient/Patient.rs')

    refresh_form = token_requests.last
    expect(refresh_form.keys).to contain_exactly(
      'grant_type', 'refresh_token', 'scope', 'client_assertion_type', 'client_assertion', 'udap'
    )
    expect(decode_assertion(refresh_form)['jti']).not_to eq(decode_assertion(exchange)['jti'])
    expect(WebMock).to have_requested(:get, well_known_url).once
    expect(warnings).to be_empty
  end

  it 'lets the application stop on a mismatched state before any token request' do
    session = client.authorization_url(verify_chain: false)
    forged = simulate_user_approval(session[:auth_url]).merge('state' => 'attacker-state')

    expect(callback_state_valid?(forged, session[:state])).to be(false)
    expect(callback_state_valid?(forged.except('state'), session[:state])).to be(false)
    expect(WebMock).not_to have_requested(:post, token_endpoint)
  end

  it 'surfaces a server PKCE rejection as TokenError when the wrong verifier is used' do
    first = client.authorization_url(verify_chain: false)
    other = client.authorization_url(verify_chain: false)
    callback = simulate_user_approval(first[:auth_url])

    expect do
      client.request_access_token(code: callback['code'], code_verifier: other[:code_verifier], verify_chain: false)
    end.to raise_error(Safire::Errors::TokenError) { |error| expect(error.error_code).to eq('invalid_grant') }
  end

  it 'warns for an unadvertised wildcard at authorization but rejects it on refresh' do
    session = client.authorization_url(scopes: ['openid', 'user/*.rs'], verify_chain: false)
    expect(Addressable::URI.parse(session[:auth_url]).query_values['scope']).to eq('openid user/*.rs')
    expect(warnings.size).to eq(1)

    expect { client.refresh_token(refresh_token: 'refresh-1', scopes: ['user/*.rs'], verify_chain: false) }
      .to raise_error(Safire::Errors::ValidationError)
    expect(WebMock).not_to have_requested(:post, token_endpoint)
  end

  describe 'Tiered OAuth (STU2 §6.1)' do
    let(:trusted_idp) { 'https://trusted-idp.example.com/oidc' }
    let(:udap_metadata) do
      super().merge(
        'udap_profiles_supported' => %w[udap_dcr udap_authn udap_to],
        'scopes_supported' => %w[openid fhirUser udap patient/*.rs]
      )
    end

    # Simulated data holder: rejects an untrusted IdP with the invalid_idp
    # extension error on the redirect URI (STU2 §6.2 MAY), otherwise approves.
    def simulate_tiered_authorization(auth_url)
      params = Addressable::URI.parse(auth_url).query_values
      return { 'error' => 'invalid_idp', 'state' => params['state'] } if params.key?('idp') &&
                                                                         params['idp'] != trusted_idp

      simulate_user_approval(auth_url)
    end

    it 'retries with a different idp after invalid_idp and completes the code exchange' do
      first = client.authorization_url(idp: 'https://unknown-idp.example.com', verify_chain: false)
      first_params = Addressable::URI.parse(first[:auth_url]).query_values
      expect(first_params['scope'].split).to eq(%w[openid fhirUser patient/Patient.rs patient/Observation.rs udap])

      rejected = simulate_tiered_authorization(first[:auth_url])
      expect(callback_state_valid?(rejected, first[:state])).to be(true)
      expect(rejected['error']).to eq('invalid_idp')

      retry_session = client.authorization_url(idp: trusted_idp, verify_chain: false)
      expect(Addressable::URI.parse(retry_session[:auth_url]).query_values['idp']).to eq(trusted_idp)
      callback = simulate_tiered_authorization(retry_session[:auth_url])
      expect(callback_state_valid?(callback, retry_session[:state])).to be(true)

      tokens = client.request_access_token(code: callback['code'], code_verifier: retry_session[:code_verifier],
                                           verify_chain: false)
      expect(tokens).to include('access_token' => 'access-1')
      expect(token_requests.last).not_to have_key('idp')
      expect(warnings).to be_empty
    end

    it 'can retry without Tiered OAuth after invalid_idp' do
      first = client.authorization_url(idp: 'https://unknown-idp.example.com', verify_chain: false)
      expect(simulate_tiered_authorization(first[:auth_url])['error']).to eq('invalid_idp')

      plain = Addressable::URI.parse(client.authorization_url(verify_chain: false)[:auth_url]).query_values
      expect(plain).not_to have_key('idp')
      expect(plain['scope'].split).not_to include('udap')
    end

    context 'when the server does not advertise Tiered OAuth' do
      let(:udap_metadata) { super().merge('udap_profiles_supported' => %w[udap_dcr udap_authn]) }

      it 'raises DiscoveryError instead of sending the request' do
        expect { client.authorization_url(idp: trusted_idp, verify_chain: false) }
          .to raise_error(Safire::Errors::DiscoveryError, /udap_to/)
      end
    end

    it 'rejects an insecure idp before discovery' do
      expect { client.authorization_url(idp: 'http://idp.example.com', verify_chain: false) }
        .to raise_error(Safire::Errors::ValidationError) { |error| expect(error.attribute).to eq(:idp) }
      expect(WebMock).not_to have_requested(:get, well_known_url)
    end
  end

  it 'rejects an insecure redirect_uri when the client is configured' do
    expect { Safire::Client.new(config.merge(redirect_uri: 'http://app.example.com/callback'), protocol: :udap) }
      .to raise_error(Safire::Errors::ConfigurationError)
  end
end
