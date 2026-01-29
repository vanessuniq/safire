# frozen_string_literal: true

require 'sinatra/base'
require 'sinatra/reloader'
require 'securerandom'
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

  private

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
end
