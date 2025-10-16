require 'active_support/all'
require_relative 'safire/version'
require_relative 'safire/errors'
require_relative 'safire/http_client'
require_relative 'safire/logger'

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
      @logger = Safire::Logger.new
      @log_level = :info
      @timeout = 30
      @user_agent = "Safire v#{Safire::VERSION}"
    end
  end
end
