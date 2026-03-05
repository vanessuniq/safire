require 'logger'
require 'active_support/all'
require 'addressable/uri'
require 'base64'

require_relative 'safire/version'
require_relative 'safire/errors'
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

    def http_client
      @http_client ||= Safire::HTTPClient.new
    end

    # Validates a token response for SMART App Launch 2.2.0 compliance.
    #
    # This is a caller-invoked helper — Safire's token exchange methods do not call this
    # automatically. Use it after {Safire::Client#request_access_token} or
    # {Safire::Client#refresh_token} when you need to verify server compliance.
    #
    # Checks all required token response fields per SMART App Launch 2.2.0 §Token Response:
    # - +access_token+ must be present (SHALL)
    # - +token_type+ must be present and exactly +"Bearer"+ (SHALL, case-sensitive)
    # - +scope+ must be present (SHALL)
    #
    # Logs a warning via {Safire.logger} for each violation found and returns false.
    # Never raises an exception.
    #
    # @param response [Hash] the token response returned by the server
    # @return [Boolean] true if the response is compliant, false otherwise
    #
    # @example
    #   token_data = client.request_access_token(code: code, code_verifier: verifier)
    #   unless Safire.token_response_valid?(token_data)
    #     # Safire has already logged the violation details
    #     raise "Server token response does not meet SMART App Launch 2.2.0 requirements"
    #   end
    def token_response_valid?(response)
      unless response.is_a?(Hash)
        Safire.logger.warn('SMART token response non-compliance: response is not a JSON object')
        return false
      end

      valid = true

      %w[access_token scope].each do |field|
        next if response[field].present?

        Safire.logger.warn(
          "SMART token response non-compliance: required field '#{field}' is missing"
        )
        valid = false
      end

      token_type_valid?(response) && valid
    end

    private

    def token_type_valid?(response)
      if response['token_type'].blank?
        Safire.logger.warn(
          "SMART token response non-compliance: required field 'token_type' is missing"
        )
        return false
      end

      return true if response['token_type'] == 'Bearer'

      Safire.logger.warn(
        "SMART token response non-compliance: token_type is #{response['token_type'].inspect}; " \
        "expected 'Bearer' (SMART App Launch 2.2.0 requires token_type \"Bearer\")"
      )
      false
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
