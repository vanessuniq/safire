# frozen_string_literal: true

require 'sinatra/base'
require 'sinatra/reloader'
require 'securerandom'

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

  # Home page
  get '/' do
    erb :index
  end
end
