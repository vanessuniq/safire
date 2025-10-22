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
    attr_accessor :configuration

    def configure
      @configuration ||= Configuration.new
      yield(configuration)
    end
  end

  class Configuration
    attr_accessor :logger, :log_level, :timeout, :user_agent

    def initialize
      @logger = Safire::SafireLogger.new
      @log_level = :info
      @timeout = 30
      @user_agent = "Safire v#{Safire::VERSION}"
    end
  end
end
