# frozen_string_literal: true

require 'pry-byebug' if ENV['RACK_ENV'] == 'development'
require 'dotenv/load'
require 'sinatra/base'
require 'securerandom'
require 'openssl'
require 'json'
require 'base64'
require 'uri'
require 'safire'
require_relative 'models/fhir_server'
require_relative 'models/udap_trust_policy'
require_relative 'models/udap_client_credentials'
require_relative 'models/udap_discovery_presenter'
require_relative 'models/udap_registration_presenter'

# Sinatra demo application for Safire gem
class SafireDemo < Sinatra::Base
  # In-memory metadata cache shared across requests (keyed by server base_url)
  METADATA_CACHE_TTL = 300 # seconds
  DEMO_LOGO_PNG = Base64.decode64(
    'iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAJklEQVR4nGNgGAWjYBSMglEwCkbBKBgF' \
    'o2AUjIJRMApGwSgYBQMAADe+ARH+ZraZAAAAAElFTkSuQmCC'
  ).freeze
  private_constant :DEMO_LOGO_PNG

  @metadata_cache = {}
  class << self
    attr_reader :metadata_cache
  end

  use Rack::Protection::AuthenticityToken, reaction: :deny

  configure :development do
    require 'sinatra/reloader'

    register Sinatra::Reloader
    also_reload File.join(__dir__, 'models', '*.rb')
  end

  configure do
    enable :sessions
    set :session_secret, ENV.fetch('SESSION_SECRET') { SecureRandom.hex(32) }
    set :views, File.join(__dir__, 'views')
    set :public_folder, File.join(__dir__, 'public')
    set :method_override, true
  end

  helpers do # rubocop:disable Metrics/BlockLength
    def redirect_uri
      "#{request.scheme}://#{request.host_with_port}/callback"
    end

    def flash
      session[:flash] || {}
    end

    def set_flash(type, message)
      session[:flash] = { type: type, message: message }
    end

    def clear_flash
      session.delete(:flash)
    end

    def h(text)
      Rack::Utils.escape_html(text.to_s)
    end

    def csrf_field
      token = Rack::Protection::AuthenticityToken.token(session)
      %(<input type="hidden" name="authenticity_token" value="#{h(token)}">)
    end

    def flash_error_message(context, error)
      "#{context}: #{error.message}"
    end

    def asymmetric_credentials_configured?
      ENV.fetch('ASYMMETRIC_PRIVATE_KEY_PEM', '').strip.length.positive? &&
        ENV.fetch('ASYMMETRIC_KID', '').strip.length.positive?
    end

    def asymmetric_private_key
      return nil unless asymmetric_credentials_configured?

      pem = ENV.fetch('ASYMMETRIC_PRIVATE_KEY_PEM', nil)
      OpenSSL::PKey.read(pem)
    rescue OpenSSL::PKey::PKeyError
      nil
    end

    def client_uri
      "#{request.scheme}://#{request.host_with_port}"
    end

    def jwks_uri
      "#{request.scheme}://#{request.host_with_port}/.well-known/jwks.json"
    end

    def localhost_policy_for(*urls)
      urls.any? { |url| http_loopback_url?(url) } ? { allow_insecure_localhost: true } : {}
    end

    def http_loopback_url?(value)
      uri = URI.parse(value.to_s)
      uri.scheme == 'http' && %w[localhost 127.0.0.1].include?(uri.host)
    rescue URI::InvalidURIError
      false
    end
  end

  before do
    @flash = flash
    clear_flash
  end

  # ============================================
  # JWKS Endpoint for Asymmetric Authentication
  # ============================================

  # Serve the client's public key as a JWKS
  # Authorization servers fetch this to verify JWT assertions
  get '/.well-known/jwks.json' do
    content_type 'application/json'

    halt 404, { error: 'No asymmetric credentials configured' }.to_json unless asymmetric_credentials_configured?

    key = asymmetric_private_key
    halt 500, { error: 'Invalid private key configuration' }.to_json unless key

    jwk = build_jwk(key, ENV.fetch('ASYMMETRIC_KID', nil))
    { keys: [jwk] }.to_json
  end

  get '/safire-demo-logo.png' do
    content_type 'image/png'
    DEMO_LOGO_PNG
  end

  # Home - list all servers
  get '/' do
    @servers = FhirServer.all
    @udap_registration_servers = @servers.select { |server| server.supports_udap? && server.udap_client_id.blank? }
    erb :index
  end

  # New server form
  get '/servers/new' do
    @server = FhirServer.new({})
    erb :'servers/new'
  end

  # Create server
  post '/servers' do
    @server = FhirServer.new(server_params)

    if @server.valid?
      @server.save
      set_flash(:success, "Server '#{@server.name}' created successfully!")
      redirect "/servers/#{@server.id}"
    else
      set_flash(:error, @server.errors.join(', '))
      erb :'servers/new'
    end
  end

  # Show server details
  get '/servers/:id' do
    @server = FhirServer.find(params[:id])
    halt 404, 'Server not found' unless @server
    @metadata = cached_server_metadata(@server) if @server.supports_smart?
    erb :'servers/show'
  end

  # Edit server form
  get '/servers/:id/edit' do
    @server = FhirServer.find(params[:id])
    halt 404, 'Server not found' unless @server
    erb :'servers/edit'
  end

  # Update server
  put '/servers/:id' do
    @server = FhirServer.find(params[:id])
    halt 404, 'Server not found' unless @server

    update_server_from_params

    if @server.valid?
      @server.save
      set_flash(:success, "Server '#{@server.name}' updated successfully!")
      redirect "/servers/#{@server.id}"
    else
      set_flash(:error, @server.errors.join(', '))
      erb :'servers/edit'
    end
  end

  # Delete server
  delete '/servers/:id' do
    server = FhirServer.find(params[:id])
    halt 404, 'Server not found' unless server

    server.destroy
    set_flash(:success, "Server '#{server.name}' deleted successfully!")
    redirect '/'
  end

  # ============================================
  # Dynamic Client Registration
  # ============================================

  # Show the DCR form — register this app to a server and create a server entry
  get '/register' do
    erb :'servers/register'
  end

  # Perform DCR — register this app with the server, then create a server entry
  # with the client_id (and optional client_secret) returned by the server
  post '/register' do
    pre_errors = validate_registration_params
    unless pre_errors.empty?
      set_flash(:error, pre_errors.join(', '))
      erb :'servers/register'
      return
    end

    @server = build_server_from_registration(perform_registration)

    if @server.valid?
      @server.save
      set_flash(:success, "Client registered — '#{@server.name}' saved with client_id: #{@server.client_id}")
      redirect "/servers/#{@server.id}"
    else
      set_flash(:error, @server.errors.join(', '))
      erb :'servers/register'
    end
  rescue Safire::Errors::Error => e
    set_flash(:error, flash_error_message('Dynamic Client Registration failed', e))
    erb :'servers/register'
  end

  # ============================================
  # Demo Routes
  # ============================================

  SMART_DEMO_FILTER_PATHS = %w[
    /demo/:server_id/discovery
    /demo/:server_id/authorize
    /demo/:server_id/backend-token
    /demo/:server_id/refresh
  ].freeze

  # Before filter for demo routes that need server and metadata
  before '/demo/:server_id/*' do
    @server = FhirServer.find(params[:server_id])
    halt 404, 'Server not found' unless @server
  end

  SMART_DEMO_FILTER_PATHS.each do |path|
    before path do
      require_smart_protocol!
      load_smart_demo_context
    end
  end

  before '/demo/:server_id/udap-discovery' do
    require_udap_protocol!
  end

  before '/demo/:server_id/udap-registration' do
    require_udap_protocol!
  end

  before '/demo/:server_id/udap-registration/cancel' do
    require_udap_protocol!
  end

  # SMART Discovery
  get '/demo/:server_id/discovery' do
    erb :'demo/discovery'
  end

  # UDAP Discovery
  get '/demo/:server_id/udap-discovery' do
    @community = normalize_optional_param(params[:community])
    @udap_trust_policy = UdapTrustPolicy.new
    @udap_metadata = discover_udap_metadata(@server, community: @community, trust_policy: @udap_trust_policy)
    @udap_metadata_valid = @udap_metadata.valid?
    @udap_presenter = UdapDiscoveryPresenter.new(
      @udap_metadata,
      metadata_valid: @udap_metadata_valid,
      trust_policy: @udap_trust_policy,
      community: @community
    )

    erb :'demo/udap_discovery'
  rescue Safire::Errors::Error => e
    set_flash(:error, flash_error_message('UDAP Discovery failed', e))
    redirect "/servers/#{@server.id}"
  end

  # UDAP Dynamic Client Registration
  get '/demo/:server_id/udap-registration' do
    @udap_registration_presenter = build_udap_registration_presenter(
      form_params: stored_udap_registration_context || params
    )

    erb :'demo/udap_registration'
  end

  post '/demo/:server_id/udap-registration' do
    # The registration request is built from normalized form values on this presenter.
    @udap_registration_presenter = build_udap_registration_presenter
    if @server.udap_client_id.present?
      @udap_registration_presenter = build_udap_registration_presenter(error: duplicate_udap_registration_error)
    elsif @udap_registration_presenter.scope.blank?
      @udap_registration_presenter = build_udap_registration_presenter(error: missing_udap_registration_scope_error)
    else
      registration = perform_udap_registration
      persist_udap_registration!(registration)
      @udap_registration_presenter = build_udap_registration_presenter(
        registration_response: registration,
        form_params: {}
      )
    end

    erb :'demo/udap_registration'
  rescue Safire::Errors::Error => e
    @udap_registration_presenter = build_udap_registration_presenter(error: e)
    erb :'demo/udap_registration'
  end

  post '/demo/:server_id/udap-registration/cancel' do
    @udap_registration_presenter = process_udap_cancellation

    erb :'demo/udap_registration'
  rescue Safire::Errors::Error => e
    @udap_registration_presenter = build_udap_registration_presenter(
      error: e,
      expected_client_id: @server.udap_client_id,
      form_params: cancellation_form_params(stored_udap_registration_context || {})
    )
    erb :'demo/udap_registration'
  end

  # Authorization flow - configuration form
  get '/demo/:server_id/authorize' do
    erb :'demo/authorize'
  end

  # Start authorization flow
  post '/demo/:server_id/authorize' do
    client_type = params[:client_type]&.to_sym || :public
    launch_type = params[:launch_type] || 'provider_standalone'

    begin
      @safire_client.client_type = client_type
      scopes = build_scopes_for_launch(launch_type, @server.scopes)
      auth_data = @safire_client.authorization_url(custom_scopes: scopes)

      store_oauth_session(auth_data, client_type, launch_type)
      redirect auth_data[:auth_url]
    rescue Safire::Errors::Error => e
      set_flash(:error, flash_error_message('Authorization failed', e))
      redirect "/servers/#{@server.id}"
    end
  end

  # Backend Services - request form
  get '/demo/:server_id/backend-token' do
    unless @metadata&.supports_backend_services?
      set_flash(:error, 'This server does not advertise the client_credentials grant.')
      redirect "/servers/#{@server.id}"
      return
    end

    @backend_scopes = backend_service_scopes(@server.scopes).join(' ')
    erb :'demo/backend_token'
  end

  # Backend Services - request token
  post '/demo/:server_id/backend-token' do
    unless asymmetric_credentials_configured?
      set_flash(:error, 'Backend Services requires ASYMMETRIC_PRIVATE_KEY_PEM and ASYMMETRIC_KID to be set.')
      redirect "/demo/#{@server.id}/backend-token"
      return
    end

    begin
      @backend_scopes = params[:scopes].to_s.strip
      scopes = parse_scopes(@backend_scopes)
      @backend_scope_error = backend_scope_error(scopes)
      if @backend_scope_error
        status 422
        return erb :'demo/backend_token'
      end

      backend_client = build_backend_services_client(@server)
      @token_response = backend_client.request_backend_token(scopes: scopes)
      @valid = backend_client.token_response_valid?(@token_response, flow: :backend_services)
      erb :'demo/backend_token'
    rescue Safire::Errors::Error => e
      set_flash(:error, flash_error_message('Backend Services token request failed', e))
      redirect "/demo/#{@server.id}/backend-token"
    end
  end

  # Token refresh
  get '/demo/:server_id/refresh' do
    unless session[:refresh_token] && session[:token_server_id] == @server.id
      set_flash(:error, 'No refresh token available for this server.')
      redirect "/servers/#{@server.id}"
      return
    end

    begin
      @old_access_token = session[:access_token]
      @token_response = @safire_client.refresh_token(refresh_token: session[:refresh_token])

      store_token_session(@token_response)

      erb :'demo/refresh'
    rescue Safire::Errors::Error => e
      set_flash(:error, flash_error_message('Token refresh failed', e))
      redirect "/servers/#{@server.id}"
    end
  end

  # EHR/Portal Launch endpoint
  # The EHR/Portal calls this URL with `launch` and `iss` parameters
  # Optional: `client_type` param to specify authentication type
  # (public, confidential_symmetric, or confidential_asymmetric)
  get '/launch' do
    launch_token = params[:launch]
    iss = params[:iss]
    client_type = parse_client_type(params[:client_type])

    unless launch_token && iss
      set_flash(:error, 'Missing required parameters: launch and iss are required for EHR launch')
      redirect '/'
      return
    end

    @server = FhirServer.find_by_base_url(iss)
    unless @server
      set_flash(:error, "No server configured for issuer: #{iss}. Please add the server first.")
      redirect '/'
      return
    end
    require_smart_protocol!

    begin
      client = build_safire_client(@server, client_type: client_type)
      scopes = build_scopes_for_launch('ehr_launch', @server.scopes)
      auth_data = client.authorization_url(launch: launch_token, custom_scopes: scopes)

      store_oauth_session(auth_data, client_type, 'ehr_launch')
      redirect auth_data[:auth_url]
    rescue Safire::Errors::Error => e
      set_flash(:error, flash_error_message('EHR launch failed', e))
      redirect "/servers/#{@server.id}"
    end
  end

  # Reset session - clear all OAuth and token data
  post '/reset-session' do
    clear_oauth_session
    clear_token_session
    set_flash(:success, 'Session cleared successfully.')
    redirect '/'
  end

  # OAuth callback
  get '/callback' do
    return handle_invalid_state unless params[:state] == session[:oauth_state]
    return handle_oauth_error if params[:error]

    @server = FhirServer.find(session[:oauth_server_id])
    halt 404, 'Server not found' unless @server

    process_token_exchange
  end

  OAUTH_SESSION_KEYS = %i[
    oauth_state oauth_code_verifier oauth_server_id oauth_client_type oauth_launch_type
  ].freeze

  TOKEN_RESPONSE_KEYS = %i[
    token_server_id access_token refresh_token token_type expires_in scope patient encounter id_token
  ].freeze

  private

  def handle_invalid_state
    set_flash(:error, 'Invalid state parameter - possible CSRF attack')
    redirect '/'
  end

  def process_token_exchange
    load_oauth_session_vars
    @token_response = exchange_code_for_token

    store_token_session(@token_response)
    clear_oauth_session

    erb :'demo/tokens'
  rescue Safire::Errors::Error => e
    set_flash(:error, flash_error_message('Token exchange failed', e))
    redirect "/servers/#{@server.id}"
  end

  def load_oauth_session_vars
    @client_type = session[:oauth_client_type]&.to_sym || :public
    @launch_type = session[:oauth_launch_type]
  end

  def exchange_code_for_token
    client = build_safire_client(@server, client_type: @client_type)
    client.request_access_token(
      code: params[:code],
      code_verifier: session[:oauth_code_verifier]
    )
  end

  def store_oauth_session(auth_data, client_type, launch_type)
    oauth_data = {
      oauth_state: auth_data[:state],
      oauth_code_verifier: auth_data[:code_verifier],
      oauth_server_id: @server.id,
      oauth_client_type: client_type.to_s,
      oauth_launch_type: launch_type
    }
    oauth_data.each { |key, value| session[key] = value }
  end

  def clear_oauth_session
    OAUTH_SESSION_KEYS.each { |key| session.delete(key) }
  end

  def store_token_session(token_response)
    TOKEN_RESPONSE_KEYS.each { |key| session[key] = token_response[key.to_s] }
    session[:token_server_id] = @server.id
  end

  def clear_token_session
    TOKEN_RESPONSE_KEYS.each { |key| session.delete(key) }
  end

  def handle_oauth_error
    error_msg = "Authorization denied: #{params[:error]}"
    error_msg += " - #{params[:error_description]}" if params[:error_description]
    set_flash(:error, error_msg)
    redirect "/servers/#{session[:oauth_server_id]}"
  end

  def build_scopes_for_launch(launch_type, server_scopes)
    base_scopes = server_scopes.dup

    case launch_type
    when 'provider_standalone', 'patient_standalone'
      base_scopes << 'launch/patient' unless base_scopes.include?('launch/patient')
    when 'ehr_launch'
      base_scopes << 'launch' unless base_scopes.include?('launch')
    end

    base_scopes
  end

  def server_params
    {
      name: params[:name],
      base_url: params[:base_url],
      protocols: Array(params[:protocols]),
      **server_registration_params
    }
  end

  def server_registration_params
    {
      client_id: normalize_optional_param(params[:client_id]),
      client_secret: normalize_optional_param(params[:client_secret]),
      scopes: parse_scopes(params[:scopes]),
      **udap_server_registration_params
    }
  end

  def udap_server_registration_params
    {
      udap_client_id: normalize_optional_param(params[:udap_client_id]),
      udap_client_uri: normalize_optional_param(params[:udap_client_uri]),
      udap_community: normalize_optional_param(params[:udap_community])
    }
  end

  def update_server_from_params
    server_params.each { |key, value| @server.send(:"#{key}=", value) }
  end

  def normalize_optional_param(value)
    value.to_s.strip.empty? ? nil : value.strip
  end

  def parse_scopes(scopes_str)
    scopes_str.to_s.split(/[,\s]+/).map(&:strip).reject(&:empty?)
  end

  def backend_service_scopes(scopes)
    Array(scopes).select { |scope| backend_service_scope?(scope) }
  end

  def backend_service_scope?(scope)
    scope.to_s.start_with?('system/')
  end

  def backend_scope_error(scopes)
    return 'Enter at least one scope before requesting a token.' if scopes.empty?
    return if scopes.all? { |scope| backend_service_scope?(scope) }

    'Enter only system/ scopes. This demo does not establish user or patient context out of band.'
  end

  def perform_registration
    base_url = params[:base_url].strip
    endpoint      = params[:registration_endpoint].presence
    temp_client   = Safire::Client.new({ base_url:, **localhost_policy_for(base_url, endpoint) })
    authorization = build_authorization_header(params[:initial_access_token], params[:token_type])
    temp_client.register_client(
      build_registration_metadata,
      registration_endpoint: endpoint,
      authorization: authorization
    )
  end

  def build_server_from_registration(registration)
    FhirServer.new(
      name: params[:name].strip,
      base_url: params[:base_url].strip,
      scopes: parse_scopes(params[:scope] || ''),
      client_id: registration['client_id'],
      client_secret: registration['client_secret'],
      protocols: ['smart']
    )
  end

  def validate_registration_params
    errors = []
    errors << 'Name is required' if params[:name].to_s.strip.empty?
    errors << 'Base URL is required' if params[:base_url].to_s.strip.empty?
    errors
  end

  def build_registration_metadata
    {
      client_name: ENV.fetch('CLIENT_NAME', 'Safire Demo App'),
      client_uri: client_uri,
      redirect_uris: [redirect_uri],
      grant_types: registration_grant_types,
      token_endpoint_auth_method: params[:token_endpoint_auth_method].presence,
      scope: params[:scope].presence,
      jwks_uri: registration_jwks_uri
    }.compact
  end

  def registration_grant_types
    Array(params[:grant_types]).reject(&:empty?)
  end

  def registration_jwks_uri
    jwks_uri if params[:include_jwks_uri] == '1' && asymmetric_credentials_configured?
  end

  def build_authorization_header(token, token_type)
    return nil unless token.present?

    "#{token_type.presence || 'Bearer'} #{token.strip}"
  end

  def parse_client_type(client_type_param)
    return :public if client_type_param.to_s.strip.empty?

    client_type = client_type_param.to_s.strip.to_sym
    %i[public confidential_symmetric confidential_asymmetric].include?(client_type) ? client_type : :public
  end

  def cached_server_metadata(server, client: nil)
    entry = SafireDemo.metadata_cache[server.base_url]
    return entry[:metadata] if fresh_cache?(entry)

    fetch_and_cache_metadata(server, client)
  end

  def fresh_cache?(entry)
    entry && Time.now.to_i - entry[:fetched_at] < METADATA_CACHE_TTL
  end

  def fetch_and_cache_metadata(server, client)
    client ||= Safire::Client.new(
      { base_url: server.base_url, client_id: server.client_id, **localhost_policy_for(server.base_url) }
    )
    metadata = client.server_metadata
    SafireDemo.metadata_cache[server.base_url] = { metadata: metadata, fetched_at: Time.now.to_i }
    metadata
  rescue Safire::Errors::Error
    nil
  end

  def load_smart_demo_context
    @safire_client = build_safire_client(@server)
    @metadata = cached_server_metadata(@server, client: @safire_client)
    return if @metadata

    set_flash(:error, 'Server discovery failed — check the server URL and try again.')
    redirect "/servers/#{@server.id}"
  end

  def require_smart_protocol!
    require_protocol!(@server.supports_smart?, 'SMART App Launch')
  end

  def require_udap_protocol!
    require_protocol!(@server.supports_udap?, 'UDAP Security')
  end

  def require_protocol!(supported, label)
    return if supported

    set_flash(:error, "#{@server.name} is not configured for #{label}.")
    redirect "/servers/#{@server.id}"
  end

  def discover_udap_metadata(server, community:, trust_policy:)
    client = Safire::Client.new(
      { base_url: server.base_url, **localhost_policy_for(server.base_url) },
      protocol: :udap
    )
    client.server_metadata(community: community, **trust_policy.server_metadata_kwargs)
  end

  def build_udap_registration_presenter(registration_response: nil, cancellation_response: nil,
                                        expected_client_id: nil, error: nil, form_params: params)
    UdapRegistrationPresenter.new(
      server: @server,
      params: form_params,
      credentials: udap_client_credentials,
      trust_policy: udap_trust_policy,
      client_uri: client_uri,
      redirect_uri: redirect_uri,
      registration_response:,
      cancellation_response:,
      expected_client_id:,
      error:
    )
  end

  def perform_udap_registration
    client = build_udap_registration_client(policy_urls: udap_registration_policy_urls)
    client.register_client(
      udap_registration_metadata(operation: :register),
      client_uri: udap_registration_client_uri,
      community: udap_registration_community,
      certifications: udap_registration_certifications,
      **udap_trust_policy.server_metadata_kwargs
    )
  end

  def perform_udap_cancellation
    client = build_udap_registration_client(policy_urls: [udap_registration_client_uri])
    client.cancel_registration(
      udap_registration_metadata(operation: :cancel),
      client_uri: udap_registration_client_uri,
      community: udap_registration_community,
      certifications: udap_registration_certifications,
      **udap_trust_policy.server_metadata_kwargs
    )
  end

  def process_udap_cancellation
    return build_udap_registration_presenter(error: missing_udap_registration_error) if @server.udap_client_id.blank?

    registration_context = stored_udap_registration_context
    unless registration_context
      return build_udap_registration_presenter(error: missing_udap_registration_context_error, form_params: {})
    end

    expected_client_id = @server.udap_client_id
    cancellation_context = cancellation_form_params(registration_context)
    @udap_registration_presenter = build_udap_registration_presenter(
      expected_client_id:,
      form_params: cancellation_context
    )
    cancellation = perform_udap_cancellation
    clear_udap_registration_if_confirmed!(expected_client_id, cancellation)
    build_udap_registration_presenter(
      cancellation_response: cancellation,
      expected_client_id:,
      form_params: registration_context
    )
  end

  def build_udap_registration_client(policy_urls:)
    Safire::Client.new(
      {
        base_url: @server.base_url,
        **udap_client_credentials.client_config_kwargs,
        **localhost_policy_for(@server.base_url, *policy_urls)
      },
      protocol: :udap
    )
  end

  def udap_registration_metadata(operation:)
    metadata = {
      client_name: @udap_registration_presenter.client_name,
      contacts: parse_list_param(@udap_registration_presenter.contacts_value),
      scope: @udap_registration_presenter.scope
    }
    return metadata if operation == :cancel

    if @udap_registration_presenter.authorization_code?
      metadata.merge(
        grant_types: %w[authorization_code refresh_token],
        redirect_uris: parse_list_param(@udap_registration_presenter.redirect_uris_value),
        logo_uri: @udap_registration_presenter.logo_uri
      )
    else
      metadata.merge(grant_types: ['client_credentials'])
    end
  end

  def udap_registration_policy_urls
    urls = [udap_registration_client_uri]
    if @udap_registration_presenter.authorization_code?
      urls.concat(parse_list_param(@udap_registration_presenter.redirect_uris_value))
      urls << @udap_registration_presenter.logo_uri
    end
    urls
  end

  def udap_registration_client_uri
    @udap_registration_presenter.client_uri
  end

  def udap_registration_community
    normalize_optional_param(@udap_registration_presenter.community)
  end

  def udap_registration_certifications
    certifications = parse_list_param(@udap_registration_presenter.certifications_value!)
    certifications.empty? ? nil : certifications
  end

  def duplicate_udap_registration_error
    Safire::Errors::ValidationError.new(
      attribute: :udap_client_id,
      reason: 'is already present; cancel the existing registration before registering again'
    )
  end

  def missing_udap_registration_error
    Safire::Errors::ValidationError.new(
      attribute: :udap_client_id,
      reason: 'is not present; register the client before cancelling registration'
    )
  end

  def missing_udap_registration_context_error
    Safire::Errors::ValidationError.new(
      attribute: :udap_client_uri,
      reason: 'is not present; edit the server with the client URI used during registration before cancelling'
    )
  end

  def missing_udap_registration_scope_error
    Safire::Errors::ValidationError.new(
      attribute: :scope,
      reason: 'must describe the access this demo client intends to request'
    )
  end

  def parse_list_param(value)
    value.to_s.split(/[,\s]+/).map(&:strip).reject(&:empty?)
  end

  def persist_udap_registration!(registration)
    @server.udap_client_id = registration.fetch('client_id')
    @server.udap_client_uri = udap_registration_client_uri
    @server.udap_community = udap_registration_community
    @server.udap_scope = effective_udap_registration_scope(registration)
    @server.save
  end

  def effective_udap_registration_scope(registration)
    returned_scope = registration['scope']
    return returned_scope.strip if returned_scope.is_a?(String) && returned_scope.present?

    @udap_registration_presenter.scope.strip
  end

  def clear_udap_registration_if_confirmed!(expected_client_id, response)
    return unless expected_client_id.present? && response['client_id'] == expected_client_id

    @server.udap_client_id = nil
    @server.udap_client_uri = nil
    @server.udap_community = nil
    @server.udap_scope = nil
    @server.save
  end

  def stored_udap_registration_context
    return unless @server.udap_client_id.present? && @server.udap_client_uri.present?

    {
      'client_uri' => @server.udap_client_uri,
      'community' => @server.udap_community,
      'scope' => @server.udap_scope.presence || @server.scopes.join(' ')
    }
  end

  def cancellation_form_params(registration_context)
    registration_context.merge('certifications' => params['certifications'])
  end

  def udap_client_credentials
    @udap_client_credentials ||= UdapClientCredentials.new
  end

  def udap_trust_policy
    @udap_trust_policy ||= UdapTrustPolicy.new
  end

  def build_safire_client(server, client_type: :public)
    config = base_safire_client_config(server)
    add_client_type_credentials!(config, server, client_type)

    Safire::Client.new(config, client_type: client_type)
  end

  def build_backend_services_client(server)
    config = backend_services_client_config(server)
    add_client_type_credentials!(config, server, :confidential_asymmetric)

    Safire::Client.new(config, client_type: :confidential_asymmetric)
  end

  def base_safire_client_config(server)
    {
      base_url: server.base_url,
      client_id: server.client_id,
      redirect_uri: redirect_uri,
      scopes: server.scopes,
      **localhost_policy_for(server.base_url, redirect_uri)
    }
  end

  def backend_services_client_config(server)
    {
      base_url: server.base_url,
      client_id: server.client_id,
      scopes: server.scopes,
      **localhost_policy_for(server.base_url)
    }
  end

  def add_client_type_credentials!(config, server, client_type)
    case client_type
    when :confidential_symmetric
      config[:client_secret] = server.client_secret
    when :confidential_asymmetric
      config[:private_key] = ENV.fetch('ASYMMETRIC_PRIVATE_KEY_PEM', nil)
      config[:kid] = ENV.fetch('ASYMMETRIC_KID', nil)
      config[:jwks_uri] = jwks_uri unless ENV['RACK_ENV'] == 'development'
    end
  end

  # Build a JWK from an OpenSSL key for the JWKS endpoint
  def build_jwk(key, kid)
    case key
    when OpenSSL::PKey::RSA
      build_rsa_jwk(key, kid)
    when OpenSSL::PKey::EC
      build_ec_jwk(key, kid)
    else
      raise ArgumentError, "Unsupported key type: #{key.class}"
    end
  end

  def build_rsa_jwk(key, kid)
    public_key = key.public_key
    {
      kty: 'RSA',
      kid: kid,
      use: 'sig',
      alg: 'RS384',
      n: base64url_encode(public_key.n.to_s(2)),
      e: base64url_encode(public_key.e.to_s(2))
    }
  end

  def build_ec_jwk(key, kid)
    public_key = key.public_key
    # Get the public key point coordinates
    point = public_key.public_key
    bn = point.to_bn(:uncompressed)
    # For P-384 curve, coordinates are 48 bytes each
    coord_size = 48
    key_bytes = bn.to_s(2)[1..] # Skip the 0x04 prefix
    x = key_bytes[0, coord_size]
    y = key_bytes[coord_size, coord_size]

    {
      kty: 'EC',
      kid: kid,
      use: 'sig',
      alg: 'ES384',
      crv: 'P-384',
      x: base64url_encode(x),
      y: base64url_encode(y)
    }
  end

  def base64url_encode(data)
    Base64.urlsafe_encode64(data, padding: false)
  end
end
