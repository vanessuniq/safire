require 'rack/mock'
require 'spec_helper'
require_relative '../../support/udap_certificate_helpers'

original_rack_env = ENV.fetch('RACK_ENV', nil)
ENV['RACK_ENV'] = 'test'
require_relative '../../../examples/sinatra_app/app'
original_rack_env.nil? ? ENV.delete('RACK_ENV') : ENV['RACK_ENV'] = original_rack_env

RSpec.describe SafireDemo do
  include UdapCertificateHelpers

  let(:request) { Rack::MockRequest.new(described_class) }
  let(:base_url) { 'https://udap-b2b.example.com/fhir' }
  let(:well_known_url) { "#{base_url}/.well-known/udap" }
  let(:token_endpoint) { "#{base_url}/token" }
  let(:community) { 'https://community.example.org/udap' }
  let(:private_key) { OpenSSL::PKey::RSA.generate(2048) }
  let(:certificate) { build_udap_certificate(key: private_key, uri_san: 'http://localhost:4567') }
  let(:credentials) do
    UdapClientCredentials.new(
      'UDAP_CLIENT_PRIVATE_KEY_PEM' => private_key.to_pem,
      'UDAP_CLIENT_CERTIFICATE_CHAIN_PEM' => certificate.to_pem
    )
  end
  let(:server) do
    FhirServer.new(
      id: 'udap-b2b',
      name: 'UDAP B2B',
      base_url:,
      protocols: ['udap'],
      scopes: ['openid'],
      udap_client_id: 'stored-udap-client',
      udap_client_uri: 'http://localhost:4567',
      udap_community: community,
      udap_scope: 'system/Patient.rs'
    )
  end
  let(:smart_server) do
    FhirServer.new(id: 'smart-only', name: 'SMART', base_url: 'https://smart.example.com/fhir',
                   protocols: ['smart'], client_id: 'smart-client')
  end
  let(:udap_metadata) do
    {
      'udap_versions_supported' => ['1'],
      'udap_profiles_supported' => %w[udap_dcr udap_authn udap_authz],
      'udap_authorization_extensions_supported' => ['hl7-b2b'],
      'udap_authorization_extensions_required' => ['hl7-b2b'],
      'udap_certifications_supported' => [],
      'grant_types_supported' => ['client_credentials'],
      'scopes_supported' => %w[system/*.rs system/Patient.rs],
      'token_endpoint' => token_endpoint,
      'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
      'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
      'registration_endpoint' => "#{base_url}/register",
      'registration_endpoint_jwt_signing_alg_values_supported' => ['RS256'],
      'signed_metadata' => 'header.payload.signature'
    }
  end
  let(:access_token) { 'eyJhbGciOiJSUzI1NiJ9.access-token-secret-middle.signature-tail' }
  let(:token_response) do
    {
      'access_token' => access_token,
      'refresh_token' => 'refresh-token-must-not-render',
      'token_type' => 'Bearer',
      'expires_in' => 3600,
      'scope' => 'system/Patient.rs'
    }
  end
  let(:token_params) do
    {
      client_id: 'stored-udap-client',
      community:,
      scope: 'system/Patient.rs',
      organization_id: 'https://fhir.example.com/Organization/123',
      organization_name: 'Example Clinic',
      purpose_of_use: "urn:oid:2.16.840.1.113883.5.8#TREAT\n",
      subject_name: '',
      consent_policy: ''
    }
  end
  let(:token_requests) { [] }

  def form_response(path, params: {})
    csrf_response = request.get('/servers/new')
    csrf_token = csrf_response.body[/name="authenticity_token" value="([^"]+)"/, 1]
    session_cookie = csrf_response['set-cookie'].to_s.split(';', 2).first

    request.post(
      path,
      'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
      'HTTP_COOKIE' => session_cookie,
      input: Rack::Utils.build_nested_query(params.merge(authenticity_token: csrf_token))
    )
  end

  def post_token(params = token_params)
    form_response('/demo/udap-b2b/udap-token', params:)
  end

  def stub_discovery(status: 200, body: udap_metadata)
    stub_request(:get, well_known_url)
      .with(query: { 'community' => community })
      .to_return(status:, body: body.to_json, headers: { 'Content-Type' => 'application/json' })
  end

  def stub_token(status: 200, body: token_response)
    stub_request(:post, token_endpoint)
      .with { |req| token_requests << req }
      .to_return(status:, body: body.to_json, headers: { 'Content-Type' => 'application/json' })
  end

  def sent_assertion_payload
    form = URI.decode_www_form(token_requests.last.body).to_h
    JWT.decode(form['client_assertion'], nil, false).first
  end

  before do
    allow(FhirServer).to receive(:find).with('udap-b2b').and_return(server)
    allow(FhirServer).to receive(:find).with('smart-only').and_return(smart_server)
    allow(UdapClientCredentials).to receive(:new).and_return(credentials)
    allow(UdapTrustPolicy).to receive(:new).and_return(UdapTrustPolicy.new({}))
    validator = instance_double(
      Safire::Protocols::UdapSignedMetadataValidator,
      signed_endpoint_claims: { 'token_endpoint' => token_endpoint, 'registration_endpoint' => "#{base_url}/register" }
    )
    allow(Safire::Protocols::UdapSignedMetadataValidator).to receive(:new).and_return(validator)
  end

  describe 'GET /demo/:server_id/udap-token' do
    it 'prefills the stored UDAP registration context and includes a CSRF token' do
      response = request.get('/demo/udap-b2b/udap-token')

      expect(response.status).to eq(200)
      expect(response.body).to include('UDAP B2B Token Request')
      expect(response.body).to include('name="client_id" value="stored-udap-client"')
      expect(response.body).to include('name="scope" value="system/Patient.rs"')
      expect(response.body).to include(%(name="community" value="#{community}"))
      expect(response.body).to include('name="authenticity_token"')
      expect(response.body).to include('name="organization_id"')
      expect(response.body).to include('name="purpose_of_use"')
    end

    it 'redirects servers that are not configured for UDAP' do
      response = request.get('/demo/smart-only/udap-token')

      expect(response.status).to be_between(300, 399)
      expect(response.location).to end_with('/servers/smart-only')
    end

    it 'links the B2B token workflow from the UDAP server detail page' do
      response = request.get('/servers/udap-b2b')

      expect(response.body).to include('/demo/udap-b2b/udap-token')
    end
  end

  describe 'POST /demo/:server_id/udap-token' do
    it 'renders the token result with the access token masked and other credentials filtered' do
      stub_discovery
      stub_token

      response = post_token

      expect(response.status).to eq(200)
      expect(response.body).to include('Token obtained.')
      expect(response.body).to include('eyJh...tail (62 characters)')
      expect(response.body).not_to include(access_token)
      expect(response.body).not_to include('access-token-secret-middle')
      expect(response.body).not_to include('refresh-token-must-not-render')
      expect(response.body).to include('3600 seconds')
      expect(response.body).to include('<span class="badge badge-scope">system/Patient.rs</span>')
    end

    it 'sends the requested scope and the hl7-b2b extension with blank members omitted' do
      stub_discovery
      stub_token

      post_token

      expect(token_requests.length).to eq(1)
      expect(URI.decode_www_form(token_requests.last.body).to_h['scope']).to eq('system/Patient.rs')
      expect(sent_assertion_payload).to include('iss' => 'stored-udap-client', 'sub' => 'stored-udap-client')
      expect(sent_assertion_payload.dig('extensions', 'hl7-b2b')).to eq(
        'version' => '1',
        'organization_id' => 'https://fhir.example.com/Organization/123',
        'organization_name' => 'Example Clinic',
        'purpose_of_use' => ['urn:oid:2.16.840.1.113883.5.8#TREAT']
      )
    end

    it 'rejects posts without a CSRF token before any network request' do
      response = request.post('/demo/udap-b2b/udap-token', params: token_params)

      expect(response.status).to eq(403)
      expect(WebMock).not_to have_requested(:any, /udap-b2b\.example\.com/)
    end

    it 'renders a ConfigurationError when the client id is blank' do
      response = post_token(token_params.merge(client_id: ' '))

      expect(response.status).to eq(200)
      expect(response.body).to include('UDAP token request failed (Configuration error).')
      expect(response.body).to include('client_id')
      expect(WebMock).not_to have_requested(:any, /udap-b2b\.example\.com/)
    end

    it 'renders a ConfigurationError when UDAP signing credentials are missing' do
      unconfigured = instance_double(UdapClientCredentials, configured?: false)
      allow(unconfigured).to receive(:client_config_kwargs).and_raise(
        Safire::Errors::ConfigurationError.new(missing_attributes: %i[UDAP_CLIENT_PRIVATE_KEY_PEM])
      )
      allow(UdapClientCredentials).to receive(:new).and_return(unconfigured)

      response = post_token

      expect(response.body).to include('UDAP token request failed (Configuration error).')
      expect(response.body).to include('UDAP_CLIENT_PRIVATE_KEY_PEM')
      expect(response.body).to include('Not configured')
      expect(WebMock).not_to have_requested(:any, /udap-b2b\.example\.com/)
    end

    it 'renders a ValidationError for missing hl7-b2b members and keeps the form input' do
      response = post_token(token_params.merge(purpose_of_use: ''))

      expect(response.body).to include('UDAP token request failed (Validation error).')
      expect(response.body).to include('purpose_of_use')
      expect(response.body).to include('name="organization_id" value="https://fhir.example.com/Organization/123"')
      expect(WebMock).not_to have_requested(:any, /udap-b2b\.example\.com/)
    end

    it 'renders a DiscoveryError when UDAP discovery fails' do
      stub_discovery(status: 404, body: { 'error' => 'not_found' })

      response = post_token

      expect(response.body).to include('UDAP token request failed (Discovery error).')
      expect(WebMock).not_to have_requested(:post, token_endpoint)
    end

    it 'renders a TokenError with the OAuth error code and escapes server text' do
      stub_discovery
      stub_token(status: 400, body: { 'error' => 'invalid_scope', 'error_description' => '<script>x</script>' })

      response = post_token

      expect(response.body).to include('UDAP token request failed (Token error).')
      expect(response.body).to include('OAuth error: <code>invalid_scope</code>')
      expect(response.body).not_to include('<script>x</script>')
      expect(response.body).to include('&lt;script&gt;x&lt;/script&gt;')
    end

    it 'renders a NetworkError when the token endpoint is unreachable' do
      stub_discovery
      stub_request(:post, token_endpoint).to_raise(Faraday::ConnectionFailed.new('connection refused'))

      response = post_token

      expect(response.body).to include('UDAP token request failed (Network error).')
    end
  end
end
