module Safire
  module Protocols
    # Prepares the client-app side of a UDAP Tiered OAuth authorization
    # request
    # ({https://hl7.org/fhir/us/udap-security/STU2/user.html#client-authorization-request-to-data-holder
    # STU2 §6.1}).
    #
    # Normative (STU2 §6.1): the client app modifies the authorization
    # request by adding +udap+ "to the list of scopes provided in the value of
    # the +scope+ query parameter" and by adding "the extension query
    # parameter +idp+ with a value equal to the base URL of the preferred OIDC
    # IdP". "The meaning of the extension parameter +idp+ is undefined if
    # +udap+ is absent from the list of requested scopes", so Safire always
    # adds +udap+ when +idp+ is given.
    #
    # Implementation choice: the IdP base URL is "the URL listed in the +iss+
    # claim of ID tokens issued by the IdP" (STU2 §6.1, citing OpenID Connect
    # Core 1.0 §2, whose text was not fetched in this environment). Safire
    # therefore requires an absolute HTTPS URL with a host and no fragment;
    # an HTTP loopback URL is accepted only when +allow_insecure_localhost+ is
    # enabled, for local development.
    #
    # Data holder ↔ IdP interactions (STU2 §6.2–§6.3) are data-holder
    # obligations and are out of scope for this client library.
    #
    # @example
    #   request = UdapTieredAuthorizationRequest.new(idp: 'https://idp.example.com/oidc')
    #   request.scopes(%w[openid patient/Patient.rs])
    #   # => ["openid", "patient/Patient.rs", "udap"]
    #   request.params
    #   # => { idp: "https://idp.example.com/oidc" }
    #
    # @api private
    class UdapTieredAuthorizationRequest
      include URIValidation

      SCOPE = 'udap'.freeze

      # @return [String] validated, frozen IdP base URL
      attr_reader :idp

      # @param idp [String] base URL (OIDC issuer) of the preferred IdP
      # @param allow_insecure_localhost [Boolean] permit an HTTP loopback IdP URL
      # @raise [Errors::ValidationError] with attribute +:idp+ when +idp+ is not
      #   an absolute HTTPS URL with a host, or has a fragment; the message never
      #   includes the value
      # @raise [Errors::ConfigurationError] when +allow_insecure_localhost+ is not a boolean
      def initialize(idp:, allow_insecure_localhost: false)
        @allow_insecure_localhost = validate_localhost_policy(allow_insecure_localhost)
        @idp = validate_idp!(idp)
        freeze
      end

      # Returns the requested scopes with +udap+ added once. Order is kept;
      # +udap+ is appended when absent.
      #
      # @param scopes [Array<String>] normalized requested scope tokens
      # @return [Array<String>]
      def scopes(scopes)
        scopes.include?(SCOPE) ? scopes.dup : [*scopes, SCOPE]
      end

      # @return [Hash{Symbol => String}] extension query parameters for the authorization request
      def params
        { idp: @idp }
      end

      private

      def validate_idp!(value)
        reason = idp_problem(value)
        raise Errors::ValidationError.new(attribute: :idp, reason:) if reason

        value.dup.freeze
      end

      def idp_problem(value)
        return 'must be a String' unless value.is_a?(String)

        case classify_uri(value, allow_insecure_localhost: @allow_insecure_localhost, allow_fragment: false)
        when :invalid then 'must be an absolute URL'
        when :non_https then 'must use HTTPS'
        when :fragment then 'must not include a fragment'
        else
          'must be an absolute URL' if Addressable::URI.parse(value).host.blank?
        end
      end
    end
  end
end
