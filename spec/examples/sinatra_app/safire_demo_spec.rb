require 'rack/mock'
require 'spec_helper'
require 'tempfile'

original_rack_env = ENV.fetch('RACK_ENV', nil)
ENV['RACK_ENV'] = 'test'
require_relative '../../../examples/sinatra_app/app'
original_rack_env.nil? ? ENV.delete('RACK_ENV') : ENV['RACK_ENV'] = original_rack_env

RSpec.describe SafireDemo do
  let(:request) { Rack::MockRequest.new(described_class) }
  let(:smart_server) { build_server('smart-only', protocols: ['smart']) }
  let(:udap_server) { build_server('udap-only', protocols: ['udap'], client_id: nil) }
  let(:registered_udap_server) do
    build_server(
      'registered-udap',
      protocols: ['udap'],
      client_id: nil,
      udap_client_id: 'stored-udap-client',
      udap_client_uri: 'http://localhost:4567',
      udap_community: 'https://community.example.org/udap',
      udap_scope: 'system/Patient.rs'
    )
  end
  let(:malicious_udap_server) do
    build_server(
      'evil-udap',
      protocols: ['udap'],
      client_id: nil,
      name: '<script>alert("xss")</script>'
    )
  end
  let(:smart_metadata) { Safire::Protocols::SmartMetadata.new(smart_metadata_hash) }
  let(:backend_smart_metadata) { Safire::Protocols::SmartMetadata.new(backend_smart_metadata_hash) }
  let(:smart_metadata_hash) do
    {
      'authorization_endpoint' => "#{smart_server.base_url}/authorize",
      'token_endpoint' => "#{smart_server.base_url}/token",
      'capabilities' => %w[launch-standalone client-public],
      'grant_types_supported' => ['authorization_code'],
      'response_types_supported' => ['code'],
      'token_endpoint_auth_methods_supported' => ['none']
    }
  end
  let(:backend_smart_metadata_hash) do
    smart_metadata_hash.merge(
      'capabilities' => %w[launch-standalone client-public client-confidential-asymmetric],
      'grant_types_supported' => %w[authorization_code client_credentials],
      'token_endpoint_auth_methods_supported' => %w[none private_key_jwt],
      'token_endpoint_auth_signing_alg_values_supported' => ['RS384']
    )
  end
  let(:udap_trust_policy) { UdapTrustPolicy.new({}) }
  let(:udap_metadata) { Safire::Protocols::UdapMetadata.new(udap_metadata_hash) }
  let(:udap_metadata_hash) do
    {
      'udap_versions_supported' => ['1'],
      'udap_profiles_supported' => %w[udap_dcr udap_authn udap_authz],
      'udap_authorization_extensions_supported' => [],
      'udap_certifications_supported' => [],
      'grant_types_supported' => ['client_credentials'],
      'scopes_supported' => ['system/*.rs'],
      'token_endpoint' => "#{udap_server.base_url}/token",
      'token_endpoint_auth_methods_supported' => ['private_key_jwt'],
      'token_endpoint_auth_signing_alg_values_supported' => ['RS256'],
      'registration_endpoint' => "#{udap_server.base_url}/register",
      'registration_endpoint_jwt_signing_alg_values_supported' => ['RS256'],
      'signed_metadata' => 'header.payload.signature'
    }
  end

  def build_server(id, protocols:, client_id: 'client-123', udap_client_id: nil,
                   udap_client_uri: nil, udap_community: nil, udap_scope: nil, name: nil)
    FhirServer.new(
      id: id,
      name: name || id.tr('-', ' ').split.map(&:capitalize).join(' '),
      base_url: "https://#{id}.example.com/fhir",
      client_id: client_id,
      udap_client_id: udap_client_id,
      udap_client_uri: udap_client_uri,
      udap_community: udap_community,
      udap_scope: udap_scope,
      scopes: %w[openid profile],
      protocols: protocols
    )
  end

  def response_for(method, path)
    request.request(method.to_s.upcase, path)
  end

  def form_response(method, path, params: {}, env: {})
    csrf_response = request.get('/servers/new')
    csrf_token = csrf_response.body[/name="authenticity_token" value="([^"]+)"/, 1]
    session_cookie = csrf_response['set-cookie'].to_s.split(';', 2).first

    request.request(
      method.to_s.upcase,
      path,
      {
        'CONTENT_TYPE' => 'application/x-www-form-urlencoded',
        'HTTP_COOKIE' => session_cookie,
        input: Rack::Utils.build_nested_query(params.merge(authenticity_token: csrf_token))
      }.merge(env)
    )
  end

  def with_env(values)
    originals = values.to_h { |key, _value| [key, ENV.fetch(key, nil)] }
    values.each { |key, value| value.nil? ? ENV.delete(key) : ENV[key] = value }
    yield
  ensure
    originals.each { |key, value| value.nil? ? ENV.delete(key) : ENV[key] = value }
  end

  def expect_local_udap_client_configuration
    expect(Safire::Client).to have_received(:new).with(
      hash_including(
        base_url: udap_server.base_url,
        allow_insecure_localhost: true,
        private_key: 'private-key',
        certificate_chain: ['certificate'],
        jwt_algorithm: 'RS256'
      ),
      protocol: :udap
    )
  end

  def expect_system_access_registration_request(scope: 'system/*.rs')
    expect(udap_client).to have_received(:register_client).with(
      hash_including(
        client_name: 'Safire Demo App',
        contacts: ['mailto:admin@example.com'],
        grant_types: ['client_credentials'],
        scope:
      ),
      client_uri: 'http://localhost:4567',
      community: 'https://community.example.org/udap',
      certifications: %w[aaa.bbb.ccc xxx.yyy.zzz],
      **udap_trust_policy.server_metadata_kwargs
    )
  end

  def expect_stored_context_cancellation_request
    expect(udap_client).to have_received(:cancel_registration).with(
      hash_including(
        client_name: 'Safire Demo App',
        contacts: ['mailto:admin@example.com'],
        scope: 'system/Patient.rs'
      ),
      client_uri: 'http://localhost:4567',
      community: 'https://community.example.org/udap',
      certifications: nil,
      **udap_trust_policy.server_metadata_kwargs
    )
  end

  def expect_response_to_hide_registration_artifacts(response)
    expect(response.body).not_to include('must.not.render')
    expect(response.body).not_to include('registration-token-must-not-render')
    expect(response.body).not_to include('access-token-must-not-render')
    expect(response.body).not_to include('cancel-registration-token-must-not-render')
    expect(response.body).not_to include('cancel-access-token-must-not-render')
    expect(response.body).not_to include('client-assertion-must-not-render')
    expect(response.body).not_to include('private-key-pem-must-not-render')
    expect(response.body).not_to include('vendor-credential-must-not-render')
    expect(response.body).not_to include('aaa.bbb.ccc')
    expect(response.body).not_to include('xxx.yyy.zzz')
    expect(response.body).not_to include('private-key')
    expect(response.body).not_to include('certificate')
  end

  def smart_dcr_form_params
    {
      name: 'Local SMART',
      base_url: 'https://smart.example.com/fhir',
      registration_endpoint: 'http://localhost:3000/register',
      grant_types: ['authorization_code'],
      token_endpoint_auth_method: 'none',
      scope: 'openid profile'
    }
  end

  def stub_successful_smart_dcr_record
    saved_server = instance_double(
      FhirServer,
      valid?: true,
      save: true,
      id: 'saved-smart',
      name: 'Local SMART',
      client_id: 'smart-client',
      errors: []
    )

    allow(FhirServer).to receive(:new).and_call_original
    allow(FhirServer).to receive(:new).with(hash_including(client_id: 'smart-client')).and_return(saved_server)
  end

  def stub_saved_server(name:)
    saved_server = instance_double(
      FhirServer,
      valid?: true,
      save: true,
      id: 'saved-udap',
      name: name,
      errors: []
    )
    allow(FhirServer).to receive(:new).and_call_original
    allow(FhirServer).to receive(:new).with(hash_including(name: name)).and_return(saved_server)
  end

  def manual_udap_server_params
    {
      name: 'HL7 Identity Match',
      base_url: 'https://identity-matching.fast.hl7.org/fhir',
      protocols: ['udap'],
      udap_client_id: 'manual-udap-client',
      udap_client_uri: 'https://client.example.com',
      udap_community: 'https://community.example.org/udap'
    }
  end

  def stub_valid_server_update(server)
    allow(server).to receive_messages(valid?: true, save: server)
  end

  def request_backend_token_with_env
    with_env('ASYMMETRIC_PRIVATE_KEY_PEM' => 'backend-private-key', 'ASYMMETRIC_KID' => 'backend-kid') do
      form_response(:post, '/demo/smart-only/backend-token', params: { scopes: 'system/*.rs' })
    end
  end

  def expect_backend_services_client_configuration
    expect(Safire::Client).to have_received(:new).with(
      satisfy do |config|
        config[:base_url] == smart_server.base_url &&
          config[:client_id] == smart_server.client_id &&
          config[:private_key] == 'backend-private-key' &&
          config[:kid] == 'backend-kid' &&
          config[:redirect_uri].nil?
      end,
      client_type: :confidential_asymmetric
    )
  end

  before do
    described_class.metadata_cache.clear
    allow(FhirServer).to receive(:find).with('smart-only').and_return(smart_server)
    allow(FhirServer).to receive(:find).with('udap-only').and_return(udap_server)
    allow(FhirServer).to receive(:find).with('registered-udap').and_return(registered_udap_server)
    allow(FhirServer).to receive(:find).with('evil-udap').and_return(malicious_udap_server)
    allow(FhirServer).to receive(:find_by_base_url).with(udap_server.base_url).and_return(udap_server)
    allow(UdapTrustPolicy).to receive(:new).and_return(udap_trust_policy)
  end

  describe 'home page' do
    it 'shows SMART DCR and eligible UDAP DCR entry points' do
      allow(FhirServer).to receive(:all).and_return([smart_server, udap_server, registered_udap_server])

      response = response_for(:get, '/')

      expect(response.status).to eq(200)
      expect(response.body).to include('SMART DCR')
      expect(response.body).to include('/register')
      expect(response.body).to include('/demo/udap-only/udap-registration')
      expect(response.body).not_to include('/demo/registered-udap/udap-registration')
    end

    it 'points users to manual setup when no unregistered UDAP server exists' do
      allow(FhirServer).to receive(:all).and_return([smart_server, registered_udap_server])

      response = response_for(:get, '/')

      expect(response.status).to eq(200)
      expect(response.body).to include('Add UDAP Server')
      expect(response.body).to include('/servers/new')
      expect(response.body).not_to include('/demo/registered-udap/udap-registration')
    end
  end

  describe 'server detail page' do
    it 'shows the UDAP registration action when a UDAP server is not registered' do
      response = response_for(:get, '/servers/udap-only')

      expect(response.status).to eq(200)
      expect(response.body).to include('Open UDAP Registration')
      expect(response.body).to include('/demo/udap-only/udap-registration')
    end

    it 'shows the UDAP registration lifecycle action when a client id is already stored' do
      response = response_for(:get, '/servers/registered-udap')

      expect(response.status).to eq(200)
      expect(response.body).to include('stored-udap-client')
      expect(response.body).not_to include('Open UDAP Registration')
      expect(response.body).to include('Manage UDAP Registration')
      expect(response.body).to include('/demo/registered-udap/udap-registration')
    end
  end

  describe 'protocol guards' do
    [
      [:get, '/demo/udap-only/discovery'],
      [:get, '/demo/udap-only/authorize'],
      [:post, '/demo/udap-only/authorize'],
      [:get, '/demo/udap-only/backend-token'],
      [:post, '/demo/udap-only/backend-token'],
      [:get, '/demo/udap-only/refresh']
    ].each do |method, path|
      it "redirects #{method.upcase} #{path} for a UDAP-only server" do
        response = method == :get ? response_for(method, path) : form_response(method, path)

        expect(response.status).to be_between(300, 399)
        expect(response.location).to end_with('/servers/udap-only')
      end
    end

    it 'redirects UDAP discovery for a SMART-only server' do
      response = response_for(:get, '/demo/smart-only/udap-discovery')

      expect(response.status).to be_between(300, 399)
      expect(response.location).to end_with('/servers/smart-only')
    end

    it 'redirects UDAP registration for a SMART-only server' do
      response = response_for(:get, '/demo/smart-only/udap-registration')

      expect(response.status).to be_between(300, 399)
      expect(response.location).to end_with('/servers/smart-only')
    end

    it 'redirects EHR launch for a UDAP-only server' do
      response = response_for(:get, '/launch?launch=abc&iss=https%3A%2F%2Fudap-only.example.com%2Ffhir')

      expect(response.status).to be_between(300, 399)
      expect(response.location).to end_with('/servers/udap-only')
    end

    it 'escapes server names rendered through flash messages' do
      redirect_response = response_for(:get, '/demo/evil-udap/discovery')

      response = request.get('/servers/evil-udap', 'HTTP_COOKIE' => redirect_response['Set-Cookie'])

      expect(response.status).to eq(200)
      expect(response.body).not_to include(malicious_udap_server.name)
      expect(response.body).to include('&lt;script&gt;alert')
      expect(response.body).to include('is not configured for SMART App Launch')
    end
  end

  describe 'SMART discovery' do
    it 'renders discovered metadata for a SMART server' do
      client = instance_double(Safire::Client, server_metadata: smart_metadata)
      allow(Safire::Client).to receive(:new).and_return(client)

      response = response_for(:get, '/demo/smart-only/discovery')

      expect(response.status).to eq(200)
      expect(response.body).to include('SMART Discovery')
      expect(response.body).to include("#{smart_server.base_url}/authorize")
    end

    it 'escapes metadata values supplied by a SMART server' do
      unsafe_value = '<script>alert("metadata")</script>'
      metadata = Safire::Protocols::SmartMetadata.new(
        smart_metadata_hash.merge(
          'authorization_endpoint' => unsafe_value,
          'capabilities' => [unsafe_value]
        )
      )
      client = instance_double(Safire::Client, server_metadata: metadata)
      allow(Safire::Client).to receive(:new).and_return(client)

      response = response_for(:get, '/demo/smart-only/discovery')

      expect(response.status).to eq(200)
      expect(response.body).not_to include(unsafe_value)
      expect(response.body).to include('&lt;script&gt;alert')
    end

    it 'redirects when SMART discovery fails before a demo route renders' do
      client = instance_double(Safire::Client)
      allow(Safire::Client).to receive(:new).and_return(client)
      allow(client).to receive(:server_metadata).and_raise(
        Safire::Errors::DiscoveryError.new(endpoint: "#{smart_server.base_url}/.well-known/smart-configuration")
      )

      response = response_for(:get, '/demo/smart-only/discovery')

      expect(response.status).to be_between(300, 399)
      expect(response.location).to end_with('/servers/smart-only')
    end
  end

  describe 'SMART authorization' do
    it 'renders the authorization form for a SMART server' do
      client = instance_double(Safire::Client, server_metadata: smart_metadata)
      allow(Safire::Client).to receive(:new).and_return(client)

      response = response_for(:get, '/demo/smart-only/authorize')

      expect(response.status).to eq(200)
      expect(response.body).to include('Authorization Flow')
      expect(response.body).to include('Provider Standalone Launch')
    end

    it 'opts into insecure localhost only for local HTTP demo callbacks' do
      client = instance_double(Safire::Client, server_metadata: smart_metadata)
      allow(Safire::Client).to receive(:new).and_return(client)

      response = request.get('/demo/smart-only/authorize', 'HTTP_HOST' => 'localhost:4567')

      expect(response.status).to eq(200)
      expect(Safire::Client).to have_received(:new)
        .with(hash_including(allow_insecure_localhost: true), client_type: :public)
    end
  end

  describe 'manual server configuration' do
    it 'renders a UDAP client id field for manually registered UDAP clients' do
      response = response_for(:get, '/servers/new')

      expect(response.status).to eq(200)
      expect(response.body).to include('UDAP Client Registration')
      expect(response.body).to include('name="udap_client_id"')
      expect(response.body).to include('name="udap_client_uri"')
      expect(response.body).to include('name="udap_community"')
    end

    it 'persists a manually entered UDAP client id on create' do
      stub_saved_server(name: 'HL7 Identity Match')

      response = form_response(:post, '/servers', params: manual_udap_server_params)

      expect(response.status).to be_between(300, 399)
      expect(FhirServer).to have_received(:new).with(
        hash_including(
          client_id: nil,
          udap_client_id: 'manual-udap-client',
          udap_client_uri: 'https://client.example.com',
          udap_community: 'https://community.example.org/udap',
          protocols: ['udap']
        )
      )
    end

    it 'updates a manually entered UDAP client id without requiring a SMART client id' do
      stub_valid_server_update(udap_server)

      response = form_response(
        :put,
        '/servers/udap-only',
        params: {
          name: 'UDAP Only',
          base_url: udap_server.base_url,
          protocols: ['udap'],
          udap_client_id: 'updated-udap-client',
          udap_client_uri: 'https://updated-client.example.com',
          udap_community: 'https://updated-community.example.com'
        }
      )

      expect(response.status).to be_between(300, 399)
      expect(udap_server.client_id).to be_nil
      expect(udap_server.udap_client_id).to eq('updated-udap-client')
      expect(udap_server.udap_client_uri).to eq('https://updated-client.example.com')
      expect(udap_server.udap_community).to eq('https://updated-community.example.com')
      expect(udap_server).to have_received(:save)
    end
  end

  describe 'SMART Backend Services' do
    let(:metadata_client) { instance_double(Safire::Client, server_metadata: backend_smart_metadata) }
    let(:backend_client) do
      instance_double(
        Safire::Client,
        request_backend_token: backend_token_response,
        token_response_valid?: true
      )
    end
    let(:backend_token_response) do
      {
        'access_token' => 'system-token',
        'token_type' => 'Bearer',
        'expires_in' => 300,
        'scope' => 'system/*.rs'
      }
    end

    it 'requests tokens with a backend-specific confidential asymmetric client' do
      allow(Safire::Client).to receive(:new).and_return(metadata_client, backend_client)

      response = request_backend_token_with_env

      expect(response.status).to eq(200)
      expect(response.body).to include('system-token')
      expect(backend_client).to have_received(:request_backend_token).with(scopes: ['system/*.rs'])
      expect(backend_client).to have_received(:token_response_valid?).with(backend_token_response,
                                                                           flow: :backend_services)
      expect_backend_services_client_configuration
    end

    it 'escapes token response values supplied by a SMART server' do
      unsafe_value = '<script>alert("token")</script>'
      allow(Safire::Client).to receive(:new).and_return(
        metadata_client,
        instance_double(
          Safire::Client,
          request_backend_token: backend_token_response.merge(
            'access_token' => unsafe_value,
            'token_type' => unsafe_value,
            'scope' => unsafe_value
          ),
          token_response_valid?: true
        )
      )

      response = request_backend_token_with_env

      expect(response.status).to eq(200)
      expect(response.body).not_to include(unsafe_value)
      expect(response.body).to include('&lt;script&gt;alert')
    end
  end

  describe 'UDAP discovery' do
    it 'renders discovered metadata for a UDAP server' do
      client = instance_double(Safire::Client)
      allow(Safire::Client).to receive(:new)
        .with({ base_url: udap_server.base_url }, protocol: :udap)
        .and_return(client)
      allow(client).to receive(:server_metadata)
        .with(community: nil, **udap_trust_policy.server_metadata_kwargs)
        .and_return(udap_metadata)

      response = response_for(:get, '/demo/udap-only/udap-discovery')

      expect(response.status).to eq(200)
      expect(response.body).to include('UDAP Discovery')
      expect(response.body).to include('Validated without chain verification')
      expect(response.body).to include('complete UDAP trust anchors and CRLs are not configured')
    end

    it 'redirects when signed metadata validation fails during discovery' do
      client = instance_double(Safire::Client)
      allow(Safire::Client).to receive(:new).and_return(client)
      allow(client).to receive(:server_metadata).and_raise(
        Safire::Errors::DiscoveryError.new(endpoint: "#{udap_server.base_url}/.well-known/udap")
      )

      response = response_for(:get, '/demo/udap-only/udap-discovery')

      expect(response.status).to be_between(300, 399)
      expect(response.location).to end_with('/servers/udap-only')
    end
  end

  describe 'UDAP registration lifecycle' do
    let(:credentials) do
      instance_double(
        UdapClientCredentials,
        configured?: true,
        client_config_kwargs: {
          private_key: 'private-key',
          certificate_chain: ['certificate'],
          jwt_algorithm: 'RS256'
        }
      )
    end
    let(:udap_client) do
      instance_double(
        Safire::Client,
        register_client: registration_response,
        cancel_registration: cancellation_response
      )
    end
    let(:registration_response) do
      {
        'client_id' => 'new-udap-client',
        'grant_types' => ['client_credentials'],
        'scope' => 'system/*.rs',
        'software_statement' => 'must.not.render',
        'registration_access_token' => 'registration-token-must-not-render',
        'access_token' => 'access-token-must-not-render',
        'client_assertion' => 'client-assertion-must-not-render',
        'private_key_pem' => 'private-key-pem-must-not-render',
        'vendor_credential' => 'vendor-credential-must-not-render'
      }
    end
    let(:cancellation_response) do
      {
        'client_id' => 'stored-udap-client',
        'grant_types' => [],
        'registration_access_token' => 'cancel-registration-token-must-not-render',
        'access_token' => 'cancel-access-token-must-not-render'
      }
    end
    let(:registration_params) do
      {
        grant_type: 'client_credentials',
        client_uri: 'http://localhost:4567',
        client_name: 'Safire Demo App',
        contacts: 'mailto:admin@example.com',
        scope: 'system/*.rs',
        community: 'https://community.example.org/udap',
        certifications: "aaa.bbb.ccc\nxxx.yyy.zzz"
      }
    end

    before do
      allow(UdapClientCredentials).to receive(:new).and_return(credentials)
      allow(Safire::Client).to receive(:new).and_return(udap_client)
      allow(udap_server).to receive(:save).and_return(udap_server)
      allow(registered_udap_server).to receive(:save).and_return(registered_udap_server)
    end

    it 'renders the registration form with client-owned defaults' do
      response = request.get('/demo/udap-only/udap-registration', 'HTTP_HOST' => 'localhost:4567')

      expect(response.status).to eq(200)
      expect(response.body).to include('UDAP Client Registration')
      expect(response.body).to include('http://localhost:4567')
      expect(response.body).to include('Safire Demo App')
      expect(response.body).to include('mailto:admin@example.com')
      expect(response.body).to include('http://localhost:4567/callback')
      expect(response.body).to include('http://localhost:4567/safire-demo-logo.png')
    end

    it 'renders a credential setup state when signing credentials are absent' do
      allow(credentials).to receive(:configured?).and_return(false)

      response = response_for(:get, '/demo/udap-only/udap-registration')

      expect(response.status).to eq(200)
      expect(response.body).to include('UDAP client signing credentials are not configured')
      expect(response.body).to include('disabled')
    end

    it 'hides the registration form when a UDAP client id is already stored' do
      response = response_for(:get, '/demo/registered-udap/udap-registration')

      expect(response.status).to eq(200)
      expect(response.body).to include('stored-udap-client')
      expect(response.body).not_to include('Register UDAP Client')
      expect(response.body).to include('Cancel UDAP Registration')
    end

    it 'registers a client, persists udap_client_id, and does not render signed artifacts' do
      response = form_response(
        :post,
        '/demo/udap-only/udap-registration',
        params: registration_params.merge(scope: 'system/Patient.rs'),
        env: { 'HTTP_HOST' => 'localhost:4567' }
      )

      expect(response.status).to eq(200)
      expect_local_udap_client_configuration
      expect_system_access_registration_request(scope: 'system/Patient.rs')
      expect(udap_server.udap_client_id).to eq('new-udap-client')
      expect(udap_server.udap_client_uri).to eq('http://localhost:4567')
      expect(udap_server.udap_community).to eq('https://community.example.org/udap')
      expect(udap_server.udap_scope).to eq('system/*.rs')
      expect(udap_server).to have_received(:save)
      expect(response.body).to include('new-udap-client')
      expect_response_to_hide_registration_artifacts(response)
    end

    it 'persists the requested scope when the registration response omits it' do
      allow(udap_client).to receive(:register_client).and_return(registration_response.except('scope'))

      form_response(
        :post,
        '/demo/udap-only/udap-registration',
        params: registration_params.merge(scope: 'system/Observation.r')
      )

      expect(udap_server.udap_scope).to eq('system/Observation.r')
    end

    it 'rejects direct registration posts when a UDAP client id is already stored' do
      response = form_response(
        :post,
        '/demo/registered-udap/udap-registration',
        params: registration_params,
        env: { 'HTTP_HOST' => 'localhost:4567' }
      )

      expect(response.status).to eq(200)
      expect(udap_client).not_to have_received(:register_client)
      expect(registered_udap_server.udap_client_id).to eq('stored-udap-client')
      expect(response.body).to include('cancel the existing registration before registering again')
    end

    it 'rejects an empty scope before invoking Safire registration' do
      response = form_response(
        :post,
        '/demo/udap-only/udap-registration',
        params: registration_params.merge(scope: '   ')
      )

      expect(response.status).to eq(200)
      expect(udap_client).not_to have_received(:register_client)
      expect(response.body).to include('Scope')
      expect(response.body).to include('must describe the access this demo client intends to request')
    end

    it 'submits authorization-code metadata with conditional client fields' do
      form_response(
        :post,
        '/demo/udap-only/udap-registration',
        params: registration_params.merge(
          grant_type: 'authorization_code',
          redirect_uris: 'http://localhost:4567/callback',
          logo_uri: 'http://localhost:4567/safire-demo-logo.png'
        ),
        env: { 'HTTP_HOST' => 'localhost:4567' }
      )

      expect(udap_client).to have_received(:register_client).with(
        hash_including(
          grant_types: %w[authorization_code refresh_token],
          redirect_uris: ['http://localhost:4567/callback'],
          logo_uri: 'http://localhost:4567/safire-demo-logo.png'
        ),
        hash_including(client_uri: 'http://localhost:4567')
      )
    end

    it 'does not opt into insecure localhost when registration URLs are remote HTTPS URLs' do
      form_response(
        :post,
        '/demo/udap-only/udap-registration',
        params: registration_params.merge(client_uri: 'https://demo.example.com'),
        env: { 'HTTP_HOST' => 'demo.example.com' }
      )

      expect(Safire::Client).to have_received(:new).with(
        satisfy do |config|
          config[:base_url] == udap_server.base_url &&
            config[:allow_insecure_localhost].nil?
        end,
        protocol: :udap
      )
    end

    it 'renders registration errors without redirecting away from the form' do
      allow(udap_client).to receive(:register_client).and_raise(
        Safire::Errors::RegistrationError.new(error_description: 'invalid software statement')
      )

      response = form_response(:post, '/demo/udap-only/udap-registration', params: registration_params)

      expect(response.status).to eq(200)
      expect(response.body).to include('invalid software statement')
      expect(response.body).to include('Safire Demo App')
    end

    it 'does not submit registration when the configured certifications file is unreadable' do
      with_env('UDAP_CLIENT_CERTIFICATIONS_FILE' => '/tmp/safire-missing-certifications.jwt') do
        response = form_response(
          :post,
          '/demo/udap-only/udap-registration',
          params: registration_params.except(:certifications).merge(use_configured_certifications: '1')
        )

        expect(response.status).to eq(200)
        expect(response.body).to include('UDAP_CLIENT_CERTIFICATIONS_FILE')
        expect(udap_client).not_to have_received(:register_client)
      end
    end

    it 'does not submit a configured certification file unless it is explicitly selected' do
      Tempfile.create('udap-certifications') do |file|
        file.write("configured.certification.jwt\n")
        file.flush

        with_env('UDAP_CLIENT_CERTIFICATIONS_FILE' => file.path) do
          form_response(
            :post,
            '/demo/udap-only/udap-registration',
            params: registration_params.except(:certifications)
          )

          expect(udap_client).to have_received(:register_client).with(
            anything,
            hash_including(certifications: nil)
          )
        end
      end
    end

    it 'submits the grant-matched configured certification when explicitly selected' do
      certification = JWT.encode({ 'grant_types' => ['client_credentials'] }, nil, 'none')

      Tempfile.create('udap-certifications') do |file|
        file.write("#{certification}\n")
        file.flush

        with_env('UDAP_CLIENT_CERTIFICATIONS_FILE' => file.path) do
          form_response(
            :post,
            '/demo/udap-only/udap-registration',
            params: registration_params.except(:certifications).merge(use_configured_certifications: '1')
          )

          expect(udap_client).to have_received(:register_client).with(
            anything,
            hash_including(certifications: [certification])
          )
        end
      end
    end

    it 'cancels registration and clears the stored UDAP client id when the response confirms the same id' do
      response = form_response(
        :post,
        '/demo/registered-udap/udap-registration/cancel',
        params: {
          client_uri: 'https://attacker.example.com',
          community: 'https://attacker.example.com/community'
        },
        env: { 'HTTP_HOST' => 'localhost:4567' }
      )

      expect(response.status).to eq(200)
      expect_stored_context_cancellation_request
      expect(registered_udap_server.udap_client_id).to be_nil
      expect(registered_udap_server.udap_client_uri).to be_nil
      expect(registered_udap_server.udap_community).to be_nil
      expect(registered_udap_server.udap_scope).to be_nil
      expect(registered_udap_server).to have_received(:save)
      expect(response.body).to include('Registration cancelled')
      expect_response_to_hide_registration_artifacts(response)
    end

    it 'submits explicitly supplied certifications during cancellation' do
      response = form_response(
        :post,
        '/demo/registered-udap/udap-registration/cancel',
        params: { certifications: "cancel.aaa.jwt\ncancel.bbb.jwt" }
      )

      expect(udap_client).to have_received(:cancel_registration).with(
        anything,
        hash_including(certifications: %w[cancel.aaa.jwt cancel.bbb.jwt])
      )
      expect(response.body).not_to include('cancel.aaa.jwt')
      expect(response.body).not_to include('cancel.bbb.jwt')
    end

    it 'does not submit cancellation when no UDAP client id is stored' do
      response = form_response(
        :post,
        '/demo/udap-only/udap-registration/cancel',
        params: registration_params,
        env: { 'HTTP_HOST' => 'localhost:4567' }
      )

      expect(response.status).to eq(200)
      expect(udap_client).not_to have_received(:cancel_registration)
      expect(response.body).to include('register the client before cancelling registration')
    end

    it 'does not submit cancellation without the stored registration identity context' do
      registered_udap_server.udap_client_uri = nil

      response = form_response(
        :post,
        '/demo/registered-udap/udap-registration/cancel',
        params: registration_params
      )

      expect(response.status).to eq(200)
      expect(udap_client).not_to have_received(:cancel_registration)
      expect(response.body).to include('client URI used during registration')
    end

    it 'preserves stored state when cancellation response confirms a different client id' do
      allow(udap_client).to receive(:cancel_registration)
        .and_return('client_id' => 'different-client', 'grant_types' => [])

      response = form_response(
        :post,
        '/demo/registered-udap/udap-registration/cancel',
        params: registration_params,
        env: { 'HTTP_HOST' => 'localhost:4567' }
      )

      expect(response.status).to eq(200)
      expect(registered_udap_server.udap_client_id).to eq('stored-udap-client')
      expect(registered_udap_server.udap_client_uri).to eq('http://localhost:4567')
      expect(registered_udap_server.udap_community).to eq('https://community.example.org/udap')
      expect(registered_udap_server.udap_scope).to eq('system/Patient.rs')
      expect(response.body).to include('different client id')
    end

    it 'rejects registration and cancellation posts without a CSRF token' do
      registration = response_for(:post, '/demo/udap-only/udap-registration')
      cancellation = response_for(:post, '/demo/registered-udap/udap-registration/cancel')

      expect(registration.status).to eq(403)
      expect(cancellation.status).to eq(403)
      expect(udap_client).not_to have_received(:register_client)
      expect(udap_client).not_to have_received(:cancel_registration)
    end
  end

  describe 'SMART Dynamic Client Registration' do
    it 'opts into insecure localhost when an explicit local registration endpoint is supplied' do
      client = instance_double(Safire::Client, register_client: { 'client_id' => 'smart-client' })
      allow(Safire::Client).to receive(:new).and_return(client)
      stub_successful_smart_dcr_record

      response = form_response(:post, '/register', params: smart_dcr_form_params)

      expect(response.status).to be_between(300, 399)
      expect(Safire::Client).to have_received(:new)
        .with(hash_including(base_url: 'https://smart.example.com/fhir', allow_insecure_localhost: true))
    end
  end
end
