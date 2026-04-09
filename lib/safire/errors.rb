module Safire
  # Namespace for all Safire error classes.
  #
  # Every Safire error inherits from {Error} so consumers can rescue
  # all Safire errors with a single +rescue Safire::Errors::Error+.
  # Each subclass exposes typed, domain-specific attributes and builds
  # its own human-readable message.
  #
  # OAuth 2.0 protocol errors ({TokenError}, {AuthError}, {RegistrationError}) share
  # the same HTTP-failure shape and inherit from {OAuthError}, which can be used as
  # a single rescue point for any server-side OAuth failure:
  #
  #   rescue Safire::Errors::OAuthError => e
  #     puts e.status       # HTTP status code
  #     puts e.error_code   # OAuth2 error field
  #
  # @example Rescuing a specific error
  #   begin
  #     tokens = client.request_access_token(code: code, code_verifier: verifier)
  #   rescue Safire::Errors::TokenError => e
  #     puts e.message        # "Token request failed — HTTP 401 — invalid_grant — Code expired"
  #     puts e.status         # 401
  #     puts e.error_code     # "invalid_grant"
  #   rescue Safire::Errors::Error => e
  #     puts e.message        # catch-all for any other Safire error
  #   end
  module Errors
    # Base class — rescue anchor only. All Safire errors inherit from this.
    class Error < StandardError; end

    # Raised when client configuration is missing or invalid.
    #
    # @!attribute [r] missing_attributes
    #   @return [Array<Symbol>] required attributes that are absent
    # @!attribute [r] invalid_attribute
    #   @return [Symbol, nil] attribute whose value is not acceptable
    # @!attribute [r] invalid_value
    #   @return [Object, nil] the offending value
    # @!attribute [r] valid_values
    #   @return [Array, nil] acceptable values for the attribute
    # @!attribute [r] invalid_uri_attributes
    #   @return [Array<Symbol>] attributes whose URIs are malformed
    # @!attribute [r] non_https_uri_attributes
    #   @return [Array<Symbol>] attributes whose URIs use HTTP on a non-localhost host
    class ConfigurationError < Error
      attr_reader :missing_attributes, :invalid_attribute, :invalid_value, :valid_values,
                  :invalid_uri_attributes, :non_https_uri_attributes

      def initialize(missing_attributes: [], invalid_attribute: nil, invalid_value: nil,
                     valid_values: nil, invalid_uri_attributes: [], non_https_uri_attributes: [])
        @missing_attributes     = Array(missing_attributes)
        @invalid_attribute      = invalid_attribute
        @invalid_value          = invalid_value
        @valid_values           = valid_values
        @invalid_uri_attributes = Array(invalid_uri_attributes)
        @non_https_uri_attributes = Array(non_https_uri_attributes)
        super(build_message)
      end

      private

      def build_message
        if @missing_attributes.any?
          "Configuration missing: #{@missing_attributes.join(', ')}"
        elsif @invalid_attribute
          "Invalid #{@invalid_attribute}: #{@invalid_value.inspect}; valid: #{@valid_values&.join(', ')}"
        else
          build_uri_message
        end
      end

      def build_uri_message
        parts = []
        parts << "Configuration has invalid URIs: #{@invalid_uri_attributes.join(', ')}" if @invalid_uri_attributes.any?
        if @non_https_uri_attributes.any?
          parts << "Configuration requires HTTPS for: #{@non_https_uri_attributes.join(', ')} " \
                   '(SMART App Launch 2.2.0 requires TLS; HTTP is only allowed for localhost)'
        end
        parts.any? ? parts.join('. ') : 'Configuration error'
      end
    end

    # Raised when SMART configuration discovery fails.
    #
    # @!attribute [r] endpoint
    #   @return [String] the discovery endpoint URL that was requested
    # @!attribute [r] status
    #   @return [Integer, nil] HTTP status code returned by the server
    # @!attribute [r] error_description
    #   @return [String, nil] description of why discovery failed (e.g. unexpected response format)
    class DiscoveryError < Error
      attr_reader :endpoint, :status, :error_description

      def initialize(endpoint:, status: nil, error_description: nil)
        @endpoint          = endpoint
        @status            = status
        @error_description = error_description
        super(build_message)
      end

      private

      def build_message
        msg = "Failed to discover SMART configuration from #{@endpoint}"
        msg += " (HTTP #{@status})" if @status
        msg += ": #{@error_description}" if @error_description
        msg
      end
    end

    # Base class for OAuth 2.0 protocol errors returned by the authorization server.
    #
    # Provides a shared structure for errors that originate from HTTP interactions
    # with OAuth 2.0 endpoints (token, authorization, registration). Subclasses define
    # {#operation_label} to set the lead phrase of the error message and may override
    # {#build_message} to handle structural failure paths (e.g. a valid HTTP response
    # that is missing a required field such as +access_token+ or +client_id+).
    #
    # Can be used as a single rescue point for any server-side OAuth protocol failure:
    #
    #   rescue Safire::Errors::OAuthError => e
    #
    # @abstract
    # @!attribute [r] status
    #   @return [Integer, nil] HTTP status code
    # @!attribute [r] error_code
    #   @return [String, nil] OAuth2 +error+ field (e.g. +"invalid_grant"+)
    # @!attribute [r] error_description
    #   @return [String, nil] OAuth2 +error_description+ field
    class OAuthError < Error
      attr_reader :status, :error_code, :error_description

      def initialize(status: nil, error_code: nil, error_description: nil)
        @status            = status
        @error_code        = error_code
        @error_description = error_description
        super(build_message)
      end

      private

      # @abstract Subclasses must define this to set the lead phrase of the error message.
      def operation_label
        raise NotImplementedError, "#{self.class} must define #operation_label"
      end

      def build_message
        parts = [operation_label]
        parts << "HTTP #{@status}" if @status
        parts << @error_code if @error_code
        parts << @error_description if @error_description
        parts.join(' — ')
      end
    end

    # Raised for token exchange or refresh failures.
    #
    # Two usage paths:
    # - HTTP failure: provide +status+, +error_code+, and/or +error_description+
    # - Structural failure (missing +access_token+): provide +received_fields+
    #
    # @!attribute [r] received_fields
    #   @return [Array<String>, nil] field names present in an invalid token response (no values logged)
    class TokenError < OAuthError
      attr_reader :received_fields

      # rubocop:disable Style/ArgumentsForwarding
      def initialize(received_fields: nil, **kwargs)
        @received_fields = received_fields
        super(**kwargs)
      end
      # rubocop:enable Style/ArgumentsForwarding

      private

      def operation_label = 'Token request failed'

      def build_message
        return "Missing access token in response; received fields: #{@received_fields.join(', ')}" if @received_fields

        super
      end
    end

    # Raised when an authorization request fails.
    #
    # @!attribute [r] status
    #   @return [Integer, nil] HTTP status code
    # @!attribute [r] error_code
    #   @return [String, nil] OAuth2 +error+ field
    # @!attribute [r] error_description
    #   @return [String, nil] OAuth2 +error_description+ field
    class AuthError < OAuthError
      private

      def operation_label = 'Authorization request failed'
    end

    # Raised when Dynamic Client Registration (RFC 7591) fails.
    #
    # Two usage paths:
    # - HTTP failure: provide +status+, +error_code+, and/or +error_description+
    # - Structural failure (missing +client_id+ in a 2xx response): provide +received_fields+
    #
    # @!attribute [r] received_fields
    #   @return [Array<String>, nil] field names present in a response missing +client_id+ (no values logged)
    class RegistrationError < OAuthError
      attr_reader :received_fields

      # rubocop:disable Style/ArgumentsForwarding
      def initialize(received_fields: nil, **kwargs)
        @received_fields = received_fields
        super(**kwargs)
      end
      # rubocop:enable Style/ArgumentsForwarding

      private

      def operation_label = 'Client registration failed'

      def build_message
        if @received_fields
          "Registration response missing client_id; received fields: #{@received_fields.join(', ')}"
        else
          super
        end
      end
    end

    # Raised for X.509 certificate errors (e.g., in UDAP flows).
    #
    # @!attribute [r] reason
    #   @return [String, nil] why the certificate is invalid (e.g. +"expired"+, +"untrusted"+)
    # @!attribute [r] subject
    #   @return [String, nil] certificate subject string (safe to log)
    class CertificateError < Error
      attr_reader :reason, :subject

      def initialize(reason: nil, subject: nil)
        @reason  = reason
        @subject = subject
        super(build_message)
      end

      private

      def build_message
        parts = ['Certificate error']
        parts << @reason if @reason
        parts << "(subject: #{@subject})" if @subject
        parts.join(' — ')
      end
    end

    # Raised when an HTTP request fails at the network or transport level
    # (connection refused, timeout, SSL handshake failure, etc.).
    #
    # @!attribute [r] error_description
    #   @return [String, nil] the underlying transport error message
    class NetworkError < Error
      attr_reader :error_description

      def initialize(error_description: nil)
        @error_description = error_description
        super(build_message)
      end

      private

      def build_message
        return 'HTTP request failed' unless @error_description

        "HTTP request failed: #{@error_description}"
      end
    end

    # Raised for input validation errors.
    #
    # @!attribute [r] attribute
    #   @return [Symbol, nil] the attribute that failed validation
    # @!attribute [r] reason
    #   @return [String, nil] why validation failed
    class ValidationError < Error
      attr_reader :attribute, :reason

      def initialize(attribute: nil, reason: nil)
        @attribute = attribute
        @reason    = reason
        super(build_message)
      end

      private

      def build_message
        if @attribute && @reason
          "Validation failed for #{@attribute}: #{@reason}"
        elsif @attribute
          "Validation failed for #{@attribute}"
        else
          'Validation error'
        end
      end
    end
  end
end
