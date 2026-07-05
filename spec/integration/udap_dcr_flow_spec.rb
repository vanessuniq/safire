require 'spec_helper'
require_relative '../support/udap_certificate_helpers'

RSpec.describe 'UDAP Dynamic Client Registration Flow', type: :integration do
  include UdapCertificateHelpers

  let(:base_url) { 'https://fhir.example.com' }
  let(:well_known_url) { "#{base_url}/.well-known/udap" }
  let(:registration_endpoint) { "#{base_url}/register" }
  let(:token_endpoint) { "#{base_url}/token" }
  let(:client_uri) { 'https://client.example.com/app' }
  let(:private_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:certificate) { build_udap_certificate(key: private_key, uri_san: client_uri) }
  let(:client) do
    Safire::Client.new(
      {
        base_url:,
        private_key:,
        certificate_chain: [certificate]
      },
      protocol: :udap
    )
  end
  let(:registration_metadata) do
    {
      client_name: 'Example Backend Service',
      contacts: ['mailto:security@example.com'],
      grant_types: ['client_credentials'],
      scope: 'system/Patient.rs'
    }
  end
  let(:cancellation_metadata) { registration_metadata.except(:grant_types) }
  let(:udap_metadata) do
    {
      'udap_versions_supported' => ['1'],
      'udap_profiles_supported' => %w[udap_dcr udap_authn udap_authz],
      'udap_authorization_extensions_supported' => [],
      'udap_certifications_supported' => [],
      'grant_types_supported' => ['client_credentials'],
      'scopes_supported' => ['system/*.rs'],
      'token_endpoint' => token_endpoint,
      'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
      'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
      'registration_endpoint' => "#{base_url}/unsigned-register",
      'registration_endpoint_jwt_signing_alg_values_supported' => ['RS256'],
      'signed_metadata' => 'eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJodHRwcyJ9.c2ln'
    }
  end
  let(:registration_response) do
    {
      'client_id' => 'udap-client-123',
      'client_name' => 'Example Backend Service'
    }
  end
  let(:registration_requests) { [] }

  def stub_udap_discovery(community: nil, body: udap_metadata)
    request = stub_request(:get, well_known_url)
    request = request.with(query: { 'community' => community }) if community
    request.to_return(status: 200, body: body.to_json, headers: { 'Content-Type' => 'application/json' })
  end

  def stub_signed_metadata_validation
    validator = instance_double(
      Safire::Protocols::UdapSignedMetadataValidator,
      signed_endpoint_claims: {
        'token_endpoint' => token_endpoint,
        'registration_endpoint' => registration_endpoint
      }
    )
    allow(Safire::Protocols::UdapSignedMetadataValidator).to receive(:new).and_return(validator)
  end

  def stub_registration_response(status: 201, body: registration_response)
    stub_request(:post, registration_endpoint)
      .with { |request| registration_requests << request.body }
      .to_return(status:, body: body.to_json, headers: { 'Content-Type' => 'application/json' })
  end

  def decoded_software_statement
    jwt = JSON.parse(registration_requests.last)['software_statement']
    JWT.decode(jwt, certificate.public_key, true, algorithms: ['RS256'], verify_expiration: false).first
  end

  before do
    stub_signed_metadata_validation
  end

  it 'discovers UDAP metadata, posts a signed registration envelope, and returns client_id' do
    stub_udap_discovery
    stub_registration_response

    result = client.register_client(registration_metadata, client_uri:)

    expect(result['client_id']).to eq('udap-client-123')
    expect(WebMock).to have_requested(:post, registration_endpoint)
  end

  it 'uses the signed registration endpoint claim as the software statement audience' do
    stub_udap_discovery
    stub_registration_response

    client.register_client(registration_metadata, client_uri:)

    payload = decoded_software_statement
    expect(payload).to include(
      'iss' => client_uri,
      'sub' => client_uri,
      'aud' => registration_endpoint,
      'client_name' => 'Example Backend Service',
      'token_endpoint_auth_method' => 'private_key_jwt'
    )
  end

  it 'scopes discovery by community when provided' do
    community = 'https://community.example.com/udap'
    stub_udap_discovery(community:)
    stub_registration_response

    client.register_client(registration_metadata, client_uri:, community:)

    expect(WebMock).to have_requested(:get, well_known_url).with(query: { 'community' => community })
  end

  it 'accepts update-style 200 registration responses when client_id is present' do
    stub_udap_discovery
    stub_registration_response(status: 200)

    expect(client.register_client(registration_metadata, client_uri:)['client_id']).to eq('udap-client-123')
  end

  it 'cancels registration with a signed empty grant_types claim' do
    stub_udap_discovery
    stub_registration_response(
      status: 202,
      body: { 'client_id' => 'udap-client-123', 'grant_types' => [] }
    )

    result = client.cancel_registration(cancellation_metadata, client_uri:)

    expect(result).to include('client_id' => 'udap-client-123', 'grant_types' => [])
    expect(decoded_software_statement).to include(
      'iss' => client_uri,
      'sub' => client_uri,
      'aud' => registration_endpoint,
      'grant_types' => []
    )
  end

  it 'uses a fresh software statement for each cancellation request' do
    stub_udap_discovery
    stub_registration_response(body: { 'client_id' => 'udap-client-123', 'grant_types' => [] })

    2.times { client.cancel_registration(cancellation_metadata, client_uri:) }

    payloads = registration_requests.map do |body|
      jwt = JSON.parse(body)['software_statement']
      JWT.decode(jwt, certificate.public_key, true, algorithms: ['RS256'], verify_expiration: false).first
    end
    expect(payloads.map { |payload| payload['jti'] }.uniq.length).to eq(2)
    expect(payloads).to all(satisfy { |payload| payload['exp'] == payload['iat'] + 300 })
  end

  it 'rejects caller-supplied cancellation grant_types before POSTing' do
    stub_udap_discovery

    expect { client.cancel_registration(registration_metadata, client_uri:) }
      .to raise_error(Safire::Errors::ValidationError, /grant_types/)
    expect(WebMock).not_to have_requested(:post, registration_endpoint)
  end

  it 'raises RegistrationError when cancellation response leaves grants active' do
    stub_udap_discovery
    stub_registration_response(body: { 'client_id' => 'udap-client-123', 'grant_types' => ['client_credentials'] })

    expect { client.cancel_registration(cancellation_metadata, client_uri:) }
      .to raise_error(Safire::Errors::RegistrationError, /empty grant_types/)
  end

  it 'raises DiscoveryError before POST when the server does not advertise UDAP DCR' do
    stub_udap_discovery(body: udap_metadata.merge('udap_profiles_supported' => %w[udap_authn udap_authz]))

    expect { client.register_client(registration_metadata, client_uri:) }
      .to raise_error(Safire::Errors::DiscoveryError, /Dynamic Client Registration/)
    expect(WebMock).not_to have_requested(:post, registration_endpoint)
  end

  it 'raises RegistrationError for a UDAP registration error response' do
    stub_udap_discovery
    stub_request(:post, registration_endpoint).to_return(
      status: 400,
      body: { 'error' => 'invalid_software_statement' }.to_json,
      headers: { 'Content-Type' => 'application/json' }
    )

    expect { client.register_client(registration_metadata, client_uri:) }
      .to raise_error(Safire::Errors::RegistrationError, /invalid_software_statement/)
  end
end
