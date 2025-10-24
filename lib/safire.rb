require 'active_support/all'

require_relative 'safire/version'
require_relative 'safire/safire_logger'
require_relative 'safire/errors'
require_relative 'safire/http_client'
require_relative 'safire/entity'

root = File.expand_path '.', File.dirname(File.absolute_path(__FILE__))
Dir.glob(File.join(root, 'safire', 'protocols', '**', '*.rb')).each do |file|
  require file
end

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
      @logger ||= configuration&.logger || default_logger
    end

    def default_logger
      @default_logger ||= Safire::SafireLogger.new
    end

    def http_client
      @http_client ||= Safire::HTTPClient.new
    end
  end

  class Configuration
    attr_accessor :logger, :user_agent

    def initialize
      @logger = Safire::SafireLogger.new
      @user_agent = "Safire v#{Safire::VERSION}"
    end
  end
end
