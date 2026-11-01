require 'spec_helper'
require_relative '../support/udap_certificate_helpers'

RSpec.describe 'UDAP B2B Client Credentials Flow', type: :integration do
  include UdapCertificateHelpers

  let(:base_url) { 'https://fhir.example.com' }
  let(:well_known_url) { "#{base_url}/.well-known/udap" }
  let(:token_endpoint) { "#{base_url}/oauth/token" }
  let(:client_id) { 'udap-client-123' }
  let(:private_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:certificate) { build_udap_certificate(key: private_key, uri_san: 'https://client.example.com/app') }
  let(:config) do
    {
      base_url:,
      client_id:,
      scopes: ['system/Patient.rs', 'system/Observation.rs'],
      private_key:,
      certificate_chain: [certificate]
    }
  end
  let(:client) { Safire::Client.new(config, protocol: :udap) }
  let(:b2b) do
    {
      organization_id: 'https://fhir.example.com/Organization/123',
      purpose_of_use: ['urn:oid:2.16.840.1.113883.5.8#TREAT'],
      subject_name: 'Dr. Example',
      subject_role: 'http://nucc.org/provider-taxonomy#207Q00000X'
    }
  end
  let(:udap_metadata) do
    {
      'udap_versions_supported' => ['1'],
      'udap_profiles_supported' => %w[udap_dcr udap_authn udap_authz],
      'udap_authorization_extensions_supported' => ['hl7-b2b'],
      'udap_authorization_extensions_required' => ['hl7-b2b'],
      'udap_certifications_supported' => [],
      'grant_types_supported' => ['client_credentials'],
      'scopes_supported' => %w[system/*.rs system/Patient.rs system/Observation.rs],
      'token_endpoint' => "#{base_url}/unsigned-token",
      'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
      'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
      'registration_endpoint' => "#{base_url}/register",
      'registration_endpoint_jwt_signing_alg_values_supported' => ['RS256'],
      'signed_metadata' => 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwcyJ9.c2ln'
    }
  end
  let(:token_response) do
    { 'access_token' => 'b2b-access-token', 'token_type' => 'Bearer', 'expires_in' => 3600,
      'scope' => 'system/Patient.rs system/Observation.rs' }
  end
  let(:token_requests) { [] }

  def stub_udap_discovery(community: nil, body: udap_metadata)
    request = stub_request(:get, well_known_url)
    request = request.with(query: { 'community' => community }) if community
    request.to_return(status: 200, body: body.to_json, headers: { 'Content-Type' => 'application/json' })
  end

  def stub_token_endpoint(status: 200, body: token_response)
    stub_request(:post, token_endpoint)
      .with { |request| token_requests << request }
      .to_return(status:, body: body.to_json, headers: { 'Content-Type' => 'application/json' })
  end

  def form_params
    URI.decode_www_form(token_requests.last.body).to_h
  end

  def decoded_assertion
    JWT.decode(form_params['client_assertion'], certificate.public_key, true, algorithms: ['RS256'])
  end

  before do
    validator = instance_double(
      Safire::Protocols::UdapSignedMetadataValidator,
      signed_endpoint_claims: { 'token_endpoint' => token_endpoint, 'registration_endpoint' => "#{base_url}/register" }
    )
    allow(Safire::Protocols::UdapSignedMetadataValidator).to receive(:new).and_return(validator)
  end

  it 'discovers trusted metadata, signs an AnT with hl7-b2b, and returns the token response' do
    stub_udap_discovery
    stub_token_endpoint

    tokens = client.request_backend_token(b2b:)

    expect(tokens['access_token']).to eq('b2b-access-token')
    expect(token_requests.length).to eq(1)
    expect(form_params).to eq(
      'grant_type' => 'client_credentials',
      'scope' => 'system/Patient.rs system/Observation.rs',
      'client_assertion_type' => 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      'client_assertion' => form_params['client_assertion'],
      'udap' => '1'
    )
    expect(token_requests.last.headers.keys.map(&:downcase)).not_to include('authorization')

    payload, header = decoded_assertion
    expect(payload).to include('iss' => client_id, 'sub' => client_id, 'aud' => token_endpoint)
    expect(payload['exp'] - payload['iat']).to eq(300)
    expect(payload.dig('extensions', 'hl7-b2b')).to include(
      'version' => '1',
      'organization_id' => 'https://fhir.example.com/Organization/123',
      'subject_name' => 'Dr. Example'
    )
    expect(header['x5c'].first).to eq(Base64.strict_encode64(certificate.to_der))
  end

  it 'scopes discovery by community and overrides configured scopes per call' do
    community = 'https://community.example.org/udap'
    stub_udap_discovery(community:)
    stub_token_endpoint

    client.request_backend_token(scopes: 'system/*.rs', b2b:, community:)

    expect(WebMock).to have_requested(:get, well_known_url).with(query: { 'community' => community })
    expect(form_params['scope']).to eq('system/*.rs')
  end

  it 'requires a new token request for a new B2B context (no caching)' do
    stub_udap_discovery
    stub_token_endpoint

    client.request_backend_token(b2b:)
    client.request_backend_token(b2b: b2b.merge(purpose_of_use: ['urn:oid:2.16.840.1.113883.5.8#HPAYMT']))

    expect(token_requests.length).to eq(2)
    expect(decoded_assertion.first.dig('extensions', 'hl7-b2b', 'purpose_of_use'))
      .to eq(['urn:oid:2.16.840.1.113883.5.8#HPAYMT'])
    expect(WebMock).to have_requested(:get, well_known_url).once
  end

  it 'rejects an unadvertised wildcard before any token POST' do
    stub_udap_discovery
    stub_token_endpoint

    expect { client.request_backend_token(scopes: ['patient/*.rs'], b2b:) }
      .to raise_error(Safire::Errors::ValidationError, /wildcard/)
    expect(token_requests).to be_empty
  end

  it 'rejects a missing b2b object before discovery' do
    expect { client.request_backend_token }.to raise_error(Safire::Errors::ValidationError, /b2b/)
    expect(WebMock).not_to have_requested(:get, well_known_url)
  end

  it 'surfaces OAuth token errors without retrying' do
    stub_udap_discovery
    stub_token_endpoint(status: 400, body: { 'error' => 'invalid_scope' })

    expect { client.request_backend_token(b2b:) }
      .to raise_error(Safire::Errors::TokenError) { |error| expect(error.error_code).to eq('invalid_scope') }
    expect(token_requests.length).to eq(1)
  end

  it 'leaves SMART Backend Services unchanged on the same facade method' do
    smart_key = OpenSSL::PKey::RSA.generate(2048)
    smart = Safire::Client.new(
      { base_url:, client_id: 'smart-client', private_key: smart_key, kid: 'kid-1',
        token_endpoint: "#{base_url}/smart-token", scopes: ['system/Patient.rs'] },
      client_type: :confidential_asymmetric
    )
    stub_request(:post, "#{base_url}/smart-token")
      .with { |request| token_requests << request }
      .to_return(status: 200, body: { 'access_token' => 'smart' }.to_json,
                 headers: { 'Content-Type' => 'application/json' })

    expect(smart.request_backend_token['access_token']).to eq('smart')
    expect(form_params).not_to have_key('udap')
    expect(form_params['client_assertion_type']).to eq('urn:ietf:params:oauth:client-assertion-type:jwt-bearer')
  end
end
