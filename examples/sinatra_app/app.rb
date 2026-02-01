# frozen_string_literal: true

require 'sinatra/base'
require 'sinatra/reloader'
require 'securerandom'
require 'safire'
require_relative 'models/fhir_server'

# Sinatra demo application for Safire gem
class SafireDemo < Sinatra::Base
  configure :development do
    register Sinatra::Reloader
  end

  configure do
    enable :sessions
    set :session_secret, ENV.fetch('SESSION_SECRET') { SecureRandom.hex(32) }
    set :views, File.join(__dir__, 'views')
    set :public_folder, File.join(__dir__, 'public')
    set :method_override, true
  end

  helpers do
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
  end

  before do
    @flash = flash
    clear_flash
  end

  # Home - list all servers
  get '/' do
    @servers = FhirServer.all
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
  # Demo Routes
  # ============================================

  # Before filter for demo routes that need server and metadata
  before '/demo/:server_id/*' do
    @server = FhirServer.find(params[:server_id])
    halt 404, 'Server not found' unless @server

    begin
      @safire_client = build_safire_client(@server)
      @metadata = @safire_client.smart_metadata
    rescue Safire::Errors::Error => e
      set_flash(:error, "Server connection failed: #{e.message}")
      redirect "/servers/#{@server.id}"
    end
  end

  # SMART Discovery
  get '/demo/:server_id/discovery' do
    erb :'demo/discovery'
  end

  # Authorization flow - configuration form
  get '/demo/:server_id/authorize' do
    erb :'demo/authorize'
  end

  # Start authorization flow
  post '/demo/:server_id/authorize' do
    auth_type = params[:auth_type]&.to_sym || :public
    launch_type = params[:launch_type] || 'provider_standalone'

    begin
      @safire_client.auth_type = auth_type
      scopes = build_scopes_for_launch(launch_type, @server.scopes)
      auth_data = @safire_client.authorize_url(custom_scopes: scopes)

      store_oauth_session(auth_data, auth_type, launch_type)
      redirect auth_data[:auth_url]
    rescue Safire::Errors::Error => e
      set_flash(:error, "Authorization failed: #{e.message}")
      redirect "/servers/#{@server.id}"
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
      @token_response = @safire_client.refresh_access_token(refresh_token: session[:refresh_token])

      store_token_session(@token_response)

      erb :'demo/refresh'
    rescue Safire::Errors::Error => e
      set_flash(:error, "Token refresh failed: #{e.message}")
      redirect "/servers/#{@server.id}"
    end
  end

  # EHR/Portal Launch endpoint
  # The EHR/Portal calls this URL with `launch` and `iss` parameters
  # Optional: `auth_type` param to specify authentication type (public or confidential_symmetric)
  get '/launch' do
    launch_token = params[:launch]
    iss = params[:iss]
    auth_type = parse_auth_type(params[:auth_type])

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

    begin
      client = build_safire_client(@server, auth_type: auth_type)
      scopes = build_scopes_for_launch('ehr_launch', @server.scopes)
      auth_data = client.authorize_url(launch: launch_token, custom_scopes: scopes)

      store_oauth_session(auth_data, auth_type, 'ehr_launch')
      redirect auth_data[:auth_url]
    rescue Safire::Errors::Error => e
      set_flash(:error, "EHR launch failed: #{e.message}")
      redirect "/servers/#{@server.id}"
    end
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
    oauth_state oauth_code_verifier oauth_server_id oauth_auth_type oauth_launch_type
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
    set_flash(:error, "Token exchange failed: #{e.message}")
    redirect "/servers/#{@server.id}"
  end

  def load_oauth_session_vars
    @auth_type = session[:oauth_auth_type]&.to_sym || :public
    @launch_type = session[:oauth_launch_type]
  end

  def exchange_code_for_token
    client = build_safire_client(@server, auth_type: @auth_type)
    client.request_access_token(
      code: params[:code],
      code_verifier: session[:oauth_code_verifier]
    )
  end

  def store_oauth_session(auth_data, auth_type, launch_type)
    oauth_data = {
      oauth_state: auth_data[:state],
      oauth_code_verifier: auth_data[:code_verifier],
      oauth_server_id: @server.id,
      oauth_auth_type: auth_type.to_s,
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
      client_id: params[:client_id],
      client_secret: normalize_optional_param(params[:client_secret]),
      scopes: parse_scopes(params[:scopes])
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

  def parse_auth_type(auth_type_param)
    return :public if auth_type_param.to_s.strip.empty?

    auth_type = auth_type_param.to_s.strip.to_sym
    %i[public confidential_symmetric].include?(auth_type) ? auth_type : :public
  end

  def build_safire_client(server, auth_type: :public)
    config = {
      base_url: server.base_url,
      client_id: server.client_id,
      redirect_uri: redirect_uri,
      scopes: server.scopes
    }
    config[:client_secret] = server.client_secret if server.client_secret

    Safire::Client.new(config, auth_type: auth_type)
  end
end
