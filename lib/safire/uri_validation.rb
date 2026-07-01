require 'addressable/uri'
require_relative 'errors'

module Safire
  # Shared URI classification for HTTPS enforcement.
  #
  # Provides {#classify_uri}, {#strict_https_uri?}, {#localhost_http_uri?}, and
  # {#localhost_host?} as private instance methods.
  # Include this module in any class that must apply Safire's localhost-aware
  # HTTPS policy or a protocol-specific strict-HTTPS requirement.
  #
  # @api private
  module URIValidation
    LOCALHOST_POLICY_VALUES = [true, false].freeze
    private_constant :LOCALHOST_POLICY_VALUES

    private

    # Classifies a URI value as +:invalid+, +:non_https+, or +nil+ (acceptable).
    #
    # HTTPS is accepted for all hosts. Plain HTTP is accepted for localhost and
    # 127.0.0.1 only when +allow_insecure_localhost+ is +true+. Any other scheme
    # (including non-HTTP schemes on localhost) returns +:non_https+.
    #
    # @param value [String, nil] the URI string to classify
    # @param allow_insecure_localhost [Boolean] whether HTTP loopback URIs are accepted
    # @return [:invalid, :non_https, nil]
    def classify_uri(value, allow_insecure_localhost: false)
      uri = Addressable::URI.parse(value)
      return :invalid unless parsed_uri_absolute?(uri)
      return if allowed_uri?(uri, allow_insecure_localhost:)

      :non_https
    rescue Addressable::URI::InvalidURIError
      :invalid
    end

    def parsed_uri_absolute?(uri)
      uri.scheme && uri.host
    end

    def allowed_uri?(uri, allow_insecure_localhost:)
      uri.scheme == 'https' ||
        (allow_insecure_localhost && uri.scheme == 'http' && localhost_host?(uri.host))
    end

    # Returns whether +value+ is an absolute HTTPS URI.
    #
    # Unlike {#classify_uri}, this predicate never permits plain HTTP on
    # localhost. Use it as the strict HTTPS primitive for protocol fields;
    # callers that provide a development-only localhost exception should
    # compose it explicitly with {#localhost_http_uri?}.
    #
    # @param value [Object] value to validate
    # @return [Boolean]
    def strict_https_uri?(value)
      return false unless value.is_a?(String)

      uri = Addressable::URI.parse(value)
      uri.scheme == 'https' && uri.host.present?
    rescue Addressable::URI::InvalidURIError
      false
    end

    # Returns whether +value+ is an absolute HTTP URI on an allowed loopback host.
    #
    # @param value [Object] value to validate
    # @return [Boolean]
    def localhost_http_uri?(value)
      return false unless value.is_a?(String)

      uri = Addressable::URI.parse(value)
      uri.scheme == 'http' && uri.host.present? && localhost_host?(uri.host)
    rescue Addressable::URI::InvalidURIError
      false
    end

    # Returns +true+ when the host is a local loopback address.
    #
    # @param host [String] the URI host
    # @return [Boolean]
    def localhost_host?(host)
      %w[localhost 127.0.0.1].include?(host)
    end

    def validate_localhost_policy(value)
      return value if LOCALHOST_POLICY_VALUES.include?(value)

      raise_invalid_localhost_policy!(value)
    end

    # Hook for including classes that need a domain-specific error type while
    # sharing the boolean localhost policy check.
    def raise_invalid_localhost_policy!(value)
      raise Errors::ConfigurationError.new(
        invalid_attribute: :allow_insecure_localhost,
        invalid_value: value,
        valid_values: LOCALHOST_POLICY_VALUES
      )
    end
  end
end
