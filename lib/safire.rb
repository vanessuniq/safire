require 'logger'
require 'active_support/all'
require 'addressable/uri'
require 'base64'

require_relative 'safire/version'
require_relative 'safire/errors'
require_relative 'safire/middleware/https_only_redirects'
require_relative 'safire/http_client'
require_relative 'safire/entity'
require_relative 'safire/pkce'
require_relative 'safire/jwt_assertion'

root = File.expand_path '.', File.dirname(File.absolute_path(__FILE__))
Dir.glob(File.join(root, 'safire', 'protocols', '**', '*.rb')).each do |file|
  require file
end

require_relative 'safire/client_config_builder'
require_relative 'safire/client_config'
require_relative 'safire/client'

# Main module for Safire gem
module Safire
  class << self
    attr_reader :configuration

    def configure
      @configuration ||= Configuration.new
      yield(configuration)
    end

    def logger
      log = configuration&.logger || default_logger
      log.level = configuration.log_level if configuration&.log_level && log.respond_to?(:level=)
      log
    end

    def default_logger
      @default_logger ||= Logger.new(ENV['SAFIRE_LOGGER'] || $stdout).tap do |l|
        l.level = Logger::INFO
      end
    end
  end

  class Configuration
    attr_accessor :logger, :log_level, :user_agent, :log_http

    def initialize
      @user_agent = "Safire v#{Safire::VERSION}"
      @log_http   = true
    end
  end
end
