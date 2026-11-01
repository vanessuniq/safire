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
  let(:host_env) { { 'HTTP_HOST' => 'localhost:4567' } }
  let(:callback_url) { 'http://localhost:4567/callback' }
  let(:base_url) { 'https://udap-auth.example.com/fhir' }
  let(:well_known_url) { "#{base_url}/.well-known/udap" }
  let(:authorization_endpoint) { "#{base_url}/authorize" }
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
      id: 'udap-auth',
      name: 'UDAP Auth',
      base_url:,
      protocols: ['udap'],
      scopes: ['openid'],
      udap_client_id: 'stored-udap-client',
      udap_client_uri: 'http://localhost:4567',
      udap_community: community,
      udap_scope: 'openid fhirUser patient/Patient.rs'
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
      'udap_authorization_extensions_supported' => [],
      'udap_certifications_supported' => [],
      'grant_types_supported' => %w[authorization_code refresh_token],
      'scopes_supported' => %w[openid fhirUser patient/Patient.rs],
      'authorization_endpoint' => authorization_endpoint,
      'token_endpoint' => token_endpoint,
      'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
      'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
      'registration_endpoint' => "#{base_url}/register",
      'registration_endpoint_jwt_signing_alg_values_supported' => ['RS256'],
      'signed_metadata' => 'header.payload.signature'
    }
  end
  let(:access_token) { 'eyJhbGciOiJSUzI1NiJ9.access-token-secret-middle.signature-tail' }
  let(:refresh_token) { 'refresh-token-secret-value-0001' }
  let(:token_response) do
    {
      'access_token' => access_token,
      'refresh_token' => refresh_token,
      'id_token' => 'id-token-must-not-render',
      'token_type' => 'Bearer',
      'expires_in' => 3600,
      'scope' => 'openid patient/Patient.rs',
      'patient' => '123'
    }
  end
  let(:start_params) { { client_id: 'stored-udap-client', community:, scope: 'openid fhirUser patient/Patient.rs' } }
  let(:token_requests) { [] }

  def csrf_session
    response = request.get('/servers/new', host_env)
    [response.body[/name="authenticity_token" value="([^"]+)"/, 1], session_cookie(response)]
  end

  def session_cookie(response)
    response['set-cookie'].to_s.split(';', 2).first
  end

  def post_form(path, params:, cookie: nil, csrf: nil)
    csrf, cookie = csrf_session if csrf.nil?
    request.post(
      path,
      host_env.merge(
        'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
        'HTTP_COOKIE' => cookie,
        input: Rack::Utils.build_nested_query(params.merge(authenticity_token: csrf))
      )
    )
  end

  # Starts the flow and returns the redirect response plus the session cookie and CSRF token.
  def start_flow(params = start_params)
    csrf, cookie = csrf_session
    response = post_form('/demo/udap-auth/udap-authorization', params:, cookie:, csrf:)
    { response:, cookie: session_cookie(response).presence || cookie, csrf: }
  end

  def auth_query(response)
    Addressable::URI.parse(response.location).query_values
  end

  def callback(cookie, query)
    request.get("/callback?#{Rack::Utils.build_query(query)}", host_env.merge('HTTP_COOKIE' => cookie))
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

  def sent_form(index = -1)
    URI.decode_www_form(token_requests[index].body).to_h
  end

  # Runs start + successful callback and returns the cookie holding the refresh token.
  def complete_exchange
    flow = start_flow
    state = auth_query(flow[:response])['state']
    response = callback(flow[:cookie], code: 'auth-code-123', state:)
    { response:, cookie: session_cookie(response).presence || flow[:cookie], csrf: flow[:csrf] }
  end

  before do
    allow(FhirServer).to receive(:find).with('udap-auth').and_return(server)
    allow(FhirServer).to receive(:find).with('smart-only').and_return(smart_server)
    allow(FhirServer).to receive(:find).with(nil).and_return(nil)
    allow(UdapClientCredentials).to receive(:new).and_return(credentials)
    allow(UdapTrustPolicy).to receive(:new).and_return(UdapTrustPolicy.new({}))
    validator = instance_double(
      Safire::Protocols::UdapSignedMetadataValidator,
      signed_endpoint_claims: {
        'authorization_endpoint' => authorization_endpoint,
        'token_endpoint' => token_endpoint,
        'registration_endpoint' => "#{base_url}/register"
      }
    )
    allow(Safire::Protocols::UdapSignedMetadataValidator).to receive(:new).and_return(validator)
  end

  describe 'GET /demo/:server_id/udap-authorization' do
    it 'prefills the stored UDAP registration context and shows the demo callback' do
      response = request.get('/demo/udap-auth/udap-authorization', host_env)

      expect(response.status).to eq(200)
      expect(response.body).to include('UDAP Authorization Code')
      expect(response.body).to include('name="client_id" value="stored-udap-client"')
      expect(response.body).to include('name="scope" value="openid fhirUser patient/Patient.rs"')
      expect(response.body).to include(%(name="community" value="#{community}"))
      expect(response.body).to include(callback_url)
      expect(response.body).to include('name="authenticity_token"')
      expect(response.body).not_to include('udap-authorization/refresh')
    end

    it 'redirects servers that are not configured for UDAP' do
      response = request.get('/demo/smart-only/udap-authorization', host_env)

      expect(response.status).to be_between(300, 399)
      expect(response.location).to end_with('/servers/smart-only')
    end

    it 'links the workflow from the UDAP server detail page' do
      response = request.get('/servers/udap-auth', host_env)

      expect(response.body).to include('/demo/udap-auth/udap-authorization')
    end
  end

  describe 'POST /demo/:server_id/udap-authorization' do
    it 'redirects to the signed authorization endpoint with the STU2 §7.2 parameters' do
      stub_discovery

      response = start_flow[:response]
      query = auth_query(response)

      expect(response.status).to eq(303).or eq(302)
      expect(response.location).to start_with("#{authorization_endpoint}?")
      expect(query.keys).to contain_exactly(
        'response_type', 'client_id', 'redirect_uri', 'scope', 'state', 'code_challenge', 'code_challenge_method'
      )
      expect(query).to include(
        'response_type' => 'code',
        'client_id' => 'stored-udap-client',
        'redirect_uri' => callback_url,
        'scope' => 'openid fhirUser patient/Patient.rs',
        'code_challenge_method' => 'S256'
      )
      expect(query['state']).to match(/\A[A-Za-z0-9_-]{43}\z/)
      expect(WebMock).not_to have_requested(:post, token_endpoint)
    end

    it 'rejects posts without a CSRF token before any network request' do
      response = request.post('/demo/udap-auth/udap-authorization', host_env.merge(params: start_params))

      expect(response.status).to eq(403)
      expect(WebMock).not_to have_requested(:any, /udap-auth\.example\.com/)
    end

    it 'renders a ConfigurationError when the client id is blank' do
      response = start_flow(start_params.merge(client_id: ' '))[:response]

      expect(response.status).to eq(200)
      expect(response.body).to include('UDAP authorization code request failed (Configuration error).')
      expect(response.body).to include('client_id')
      expect(WebMock).not_to have_requested(:any, /udap-auth\.example\.com/)
    end

    it 'renders a ConfigurationError when UDAP signing credentials are missing' do
      unconfigured = instance_double(UdapClientCredentials, configured?: false)
      allow(unconfigured).to receive(:client_config_kwargs).and_raise(
        Safire::Errors::ConfigurationError.new(missing_attributes: %i[UDAP_CLIENT_PRIVATE_KEY_PEM])
      )
      allow(UdapClientCredentials).to receive(:new).and_return(unconfigured)

      response = start_flow[:response]

      expect(response.body).to include('UDAP authorization code request failed (Configuration error).')
      expect(response.body).to include('UDAP_CLIENT_PRIVATE_KEY_PEM')
      expect(WebMock).not_to have_requested(:any, /udap-auth\.example\.com/)
    end

    it 'renders a DiscoveryError when the server does not advertise authorization_code' do
      stub_discovery(body: udap_metadata.merge('grant_types_supported' => ['client_credentials']))

      response = start_flow[:response]

      expect(response.status).to eq(200)
      expect(response.body).to include('UDAP authorization code request failed (Discovery error).')
    end
  end

  describe 'GET /callback for a pending UDAP authorization' do
    it 'refuses a mismatched state without requesting a token and discards the pending state' do
      stub_discovery
      stub_token
      flow = start_flow
      state = auth_query(flow[:response])['state']

      refused = callback(flow[:cookie], code: 'auth-code-123', state: "#{state}x")
      retry_response = callback(session_cookie(refused).presence || flow[:cookie], code: 'auth-code-123', state:)

      expect(refused.status).to be_between(300, 399)
      expect(refused.location).to end_with('/')
      expect(retry_response.status).to be_between(300, 399)
      expect(WebMock).not_to have_requested(:post, token_endpoint)
    end

    it 'refuses a callback without a state parameter' do
      stub_discovery
      stub_token
      flow = start_flow

      response = callback(flow[:cookie], code: 'auth-code-123')
      follow = request.get('/', host_env.merge('HTTP_COOKIE' => session_cookie(response).presence || flow[:cookie]))

      expect(response.status).to be_between(300, 399)
      expect(follow.body).to include('Invalid or missing state parameter')
      expect(WebMock).not_to have_requested(:post, token_endpoint)
    end

    it 'refuses a callback when no authorization is pending' do
      response = callback(csrf_session.last, code: 'auth-code-123', state: '')

      expect(response.status).to be_between(300, 399)
      expect(WebMock).not_to have_requested(:any, /udap-auth\.example\.com/)
    end

    it 'reports an authorization error response without requesting a token' do
      stub_discovery
      stub_token
      flow = start_flow
      state = auth_query(flow[:response])['state']

      response = callback(flow[:cookie], state:, error: 'access_denied', error_description: '<b>User denied</b>')

      expect(response.status).to eq(200)
      expect(response.body).to include('Authorization denied by the server. No token was requested.')
      expect(response.body).to include('<code>access_denied</code>')
      expect(response.body).to include('&lt;b&gt;User denied&lt;/b&gt;')
      expect(WebMock).not_to have_requested(:post, token_endpoint)
    end

    it 'exchanges the code and renders a masked token result' do
      stub_discovery
      stub_token

      response = complete_exchange[:response]

      expect(response.status).to eq(200)
      expect(response.body).to include('Authorization code exchanged.')
      expect(response.body).to include('eyJh...tail (62 characters)')
      expect(response.body).to include('Issued (not displayed)')
      expect(response.body).to include('<span class="badge badge-scope">patient/Patient.rs</span>')
      expect(response.body).to include('udap-authorization/refresh')
      [access_token, 'access-token-secret-middle', refresh_token, 'id-token-must-not-render'].each do |secret|
        expect(response.body).not_to include(secret)
      end
    end

    it 'sends the code, PKCE verifier, and demo callback in the token request' do
      stub_discovery
      stub_token
      flow = start_flow
      query = auth_query(flow[:response])

      callback(flow[:cookie], code: 'auth-code-123', state: query['state'])
      form = sent_form
      expected_challenge = Base64.urlsafe_encode64(Digest::SHA256.digest(form['code_verifier']), padding: false)

      expect(token_requests.length).to eq(1)
      expect(form).to include('grant_type' => 'authorization_code', 'code' => 'auth-code-123',
                              'redirect_uri' => callback_url, 'udap' => '1')
      expect(query['code_challenge']).to eq(expected_challenge)
      expect(JWT.decode(form['client_assertion'], nil, false).first).to include('iss' => 'stored-udap-client')
    end

    it 'uses the state only once' do
      stub_discovery
      stub_token
      flow = start_flow
      state = auth_query(flow[:response])['state']
      first = callback(flow[:cookie], code: 'auth-code-123', state:)

      replay = callback(session_cookie(first).presence || flow[:cookie], code: 'auth-code-123', state:)

      expect(replay.status).to be_between(300, 399)
      expect(token_requests.length).to eq(1)
    end

    it 'renders a TokenError with the OAuth error code and escapes server text' do
      stub_discovery
      stub_token(status: 400, body: { 'error' => 'invalid_grant', 'error_description' => '<script>x</script>' })

      response = complete_exchange[:response]

      expect(response.body).to include('UDAP authorization code request failed (Token error).')
      expect(response.body).to include('OAuth error: <code>invalid_grant</code>')
      expect(response.body).not_to include('<script>x</script>')
    end

    it 'renders a ValidationError when the callback has no code' do
      stub_discovery
      stub_token
      flow = start_flow
      state = auth_query(flow[:response])['state']

      response = callback(flow[:cookie], state:)

      expect(response.body).to include('UDAP authorization code request failed (Validation error).')
      expect(WebMock).not_to have_requested(:post, token_endpoint)
    end

    it 'renders a NetworkError when the token endpoint is unreachable' do
      stub_discovery
      stub_request(:post, token_endpoint).to_raise(Faraday::ConnectionFailed.new('connection refused'))

      response = complete_exchange[:response]

      expect(response.body).to include('UDAP authorization code request failed (Network error).')
    end
  end

  describe 'UDAP Tiered OAuth (STU2 user.md §6)' do
    let(:idp) { 'https://idp.example.com/oidc' }
    let(:tiered_metadata) do
      udap_metadata.merge(
        'udap_profiles_supported' => %w[udap_dcr udap_authn udap_authz udap_to],
        'scopes_supported' => %w[openid fhirUser patient/Patient.rs udap]
      )
    end

    it 'shows the optional Preferred IdP field and the udap_to note on the start form' do
      response = request.get('/demo/udap-auth/udap-authorization', host_env)

      expect(response.body).to include('Preferred IdP (Tiered OAuth, optional)')
      expect(response.body).to include('name="idp" value=""')
      expect(response.body).to include('Safire adds the <code>udap</code> scope')
      expect(response.body).to include('<code>udap_to</code>')
    end

    it 'adds the idp parameter and the udap scope when a preferred IdP is given' do
      stub_discovery(body: tiered_metadata)

      response = start_flow(start_params.merge(idp: " #{idp} "))[:response]
      query = auth_query(response)

      expect(response.location).to start_with("#{authorization_endpoint}?")
      expect(query['idp']).to eq(idp)
      expect(query['scope']).to eq('openid fhirUser patient/Patient.rs udap')
      expect(query).to include('response_type' => 'code', 'code_challenge_method' => 'S256')
    end

    it 'sends a standard request without udap or idp when the preferred IdP is blank' do
      stub_discovery

      query = auth_query(start_flow(start_params.merge(idp: '   '))[:response])

      expect(query).not_to have_key('idp')
      expect(query['scope']).to eq('openid fhirUser patient/Patient.rs')
    end

    it 'renders a ValidationError for an invalid IdP without discovery or redirect' do
      response = start_flow(start_params.merge(idp: 'http://idp.example.com/oidc'))[:response]

      expect(response.status).to eq(200)
      expect(response.body).to include('UDAP authorization code request failed (Validation error).')
      expect(response.body).to include('idp')
      expect(response.body).to include('name="idp" value="http://idp.example.com/oidc"')
      expect(WebMock).not_to have_requested(:any, /udap-auth\.example\.com/)
    end

    it 'renders a DiscoveryError when the server does not advertise udap_to' do
      stub_discovery(body: udap_metadata.merge('scopes_supported' => %w[openid udap]))

      response = start_flow(start_params.merge(idp:))[:response]

      expect(response.status).to eq(200)
      expect(response.body).to include('UDAP authorization code request failed (Discovery error).')
      expect(response.body).to include('udap_to')
    end

    it 'reports invalid_idp after verifying state, suggests a retry, and requests no token' do
      stub_discovery(body: tiered_metadata)
      stub_token
      flow = start_flow(start_params.merge(idp:))
      state = auth_query(flow[:response])['state']

      response = callback(flow[:cookie], state:, error: 'invalid_idp', error_description: 'IdP not trusted')

      expect(response.status).to eq(200)
      expect(response.body).to include('The data holder rejected the preferred IdP (Tiered OAuth).')
      expect(response.body).to include('<code>invalid_idp</code>')
      expect(response.body).to include('with a different Preferred IdP, or leave Preferred IdP blank')
      expect(response.body).not_to include('Authorization denied by the server.')
      expect(WebMock).not_to have_requested(:post, token_endpoint)
    end

    it 'refuses an invalid_idp callback whose state does not match' do
      stub_discovery(body: tiered_metadata)
      stub_token
      flow = start_flow(start_params.merge(idp:))
      state = auth_query(flow[:response])['state']

      response = callback(flow[:cookie], state: "#{state}x", error: 'invalid_idp')

      expect(response.status).to be_between(300, 399)
      expect(response.location).to end_with('/')
      expect(WebMock).not_to have_requested(:post, token_endpoint)
    end
  end

  describe 'POST /demo/:server_id/udap-authorization/refresh' do
    it 'refreshes with the stored refresh token and renders a masked result' do
      stub_discovery
      stub_token
      exchanged = complete_exchange
      rotated = token_response.merge('access_token' => 'rotated-access-token-value-abcdefghij',
                                     'refresh_token' => 'rotated-refresh-token-0002')
      stub_token(body: rotated)

      response = post_form('/demo/udap-auth/udap-authorization/refresh',
                           params: { refresh_scope: '' }, cookie: exchanged[:cookie], csrf: exchanged[:csrf])

      expect(response.status).to eq(200)
      expect(response.body).to include('Token refreshed.')
      expect(response.body).to include('rota...ghij (37 characters)')
      expect(response.body).not_to include('rotated-refresh-token-0002')
      expect(sent_form).to include('grant_type' => 'refresh_token', 'refresh_token' => refresh_token)
      expect(sent_form).not_to have_key('scope')
    end

    def refresh_twice(exchanged, first_params)
      first = post_form('/demo/udap-auth/udap-authorization/refresh',
                        params: first_params, cookie: exchanged[:cookie], csrf: exchanged[:csrf])
      next_cookie = session_cookie(first).presence || exchanged[:cookie]
      post_form('/demo/udap-auth/udap-authorization/refresh', params: {}, cookie: next_cookie, csrf: exchanged[:csrf])
    end

    it 'sends an optional narrower scope and uses a rotated refresh token for the next refresh' do
      stub_discovery
      stub_token
      exchanged = complete_exchange
      stub_token(body: token_response.merge('refresh_token' => 'rotated-refresh-token-0002'))

      refresh_twice(exchanged, { refresh_scope: 'patient/Patient.rs' })

      expect(sent_form(1)).to include('refresh_token' => refresh_token, 'scope' => 'patient/Patient.rs')
      expect(sent_form(2)).to include('refresh_token' => 'rotated-refresh-token-0002')
    end

    it 'keeps the previous refresh token when the refresh response does not rotate it' do
      stub_discovery
      stub_token
      exchanged = complete_exchange
      stub_token(body: token_response.except('refresh_token'))

      refresh_twice(exchanged, {})

      expect(sent_form(2)).to include('refresh_token' => refresh_token)
    end

    it 'renders a ValidationError when the session holds no refresh token' do
      response = post_form('/demo/udap-auth/udap-authorization/refresh', params: {})

      expect(response.status).to eq(200)
      expect(response.body).to include('UDAP authorization code request failed (Validation error).')
      expect(response.body).to include('refresh_token')
      expect(WebMock).not_to have_requested(:any, /udap-auth\.example\.com/)
    end

    it 'rejects posts without a CSRF token' do
      response = request.post('/demo/udap-auth/udap-authorization/refresh', host_env)

      expect(response.status).to eq(403)
      expect(WebMock).not_to have_requested(:any, /udap-auth\.example\.com/)
    end

    it 'renders a TokenError when the server rejects the refresh token' do
      stub_discovery
      stub_token
      exchanged = complete_exchange
      stub_token(status: 400, body: { 'error' => 'invalid_grant' })

      response = post_form('/demo/udap-auth/udap-authorization/refresh',
                           params: {}, cookie: exchanged[:cookie], csrf: exchanged[:csrf])

      expect(response.body).to include('UDAP authorization code request failed (Token error).')
      expect(response.body).to include('OAuth error: <code>invalid_grant</code>')
    end
  end
end
