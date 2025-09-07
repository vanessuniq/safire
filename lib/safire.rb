# lib/safire.rb
require 'active_support/all'
require_relative 'safire/version'

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
      @logger = Logger.new($stdout)
      @log_level = :info
      @timeout = 30
      @user_agent = "Safire v#{Safire::VERSION}"
    end
  end
end
