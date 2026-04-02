module Safire
  module Protocols
    # SMART Metadata obtained from SMART on FHIR discovery endpoint. Attributes are defined
    # as per [SMART on FHIR specification](https://build.fhir.org/ig/HL7/smart-app-launch/conformance.html#using-well-known)
    #
    # @!attribute [r] issuer
    #   @return [String] conveying this system’s OpenID Connect Issuer URL. Required if the server’s
    #     capabilities include sso-openid-connect.
    # @!attribute [r] jwks_uri
    #   @return [String] URL of the server’s JSON Web Key Set endpoint. Required if the server’s capabilities
    #     include sso-openid-connect.
    # @!attribute [r] authorization_endpoint
    #   @return [String] URL of the server’s OAuth2 Authorization Endpoint. Required if the server’s capabilities
    #     include launch-standalone or launch-ehr-launch.
    # @!attribute [r] grant_types_supported
    #   @return [Array<String>] list of OAuth2 grant types supported at the token endpoint.
    # @!attribute [r] token_endpoint
    #   @return [String] URL of the server’s OAuth2 Token Endpoint.
    # @!attribute [r] token_endpoint_auth_methods_supported
    #   @return [Array<String>] list of client authentication methods supported at the token endpoint.
    #     Optionally provided.
    # @!attribute [r] token_endpoint_auth_signing_alg_values_supported
    #   @return [Array<String>] list of signing algorithms supported for JWT-based client authentication.
    #     Optionally provided. Used for confidential asymmetric authentication.
    # @!attribute [r] registration_endpoint
    #   @return [String] URL of the server’s OAuth2 Dynamic Client Registration Endpoint. Optionally provided.
    # @!attribute [r] associated_endpoints
    #   @return [Array<Hash>] list of objects for endpoints that share the same authorization mechanism
    #     as this FHIR endpoint, each with a “url” and “capabilities” array. Optionally provided.
    # @!attribute [r] user_access_brand_bundle
    #   @return [String] URL for a Brand Bundle for user-facing applications. Optionally provided.
    # @!attribute [r] user_access_brand_identifier
    #   @return [String] Identifier for the primary entry in a Brand Bundle. Optionally provided.
    # @!attribute [r] scopes_supported
    #   @return [Array<String>] list of scopes a client may request. Optionally provided.
    # @!attribute [r] response_types_supported
    #   @return [Array<String>] list of OAuth2 response types supported. Optionally provided.
    # @!attribute [r] management_endpoint
    #   @return [String] URL where an end-user can view which applications currently have access to data
    #     and can make adjustments to these access rights. Optionally provided.
    # @!attribute [r] introspection_endpoint
    #   @return [String] URL to a server’s introspection endpoint that can be used to validate a token.
    #     Optionally provided.
    # @!attribute [r] revocation_endpoint
    #   @return [String] URL to a server’s revocation endpoint that can be used to revoke a token.
    #     Optionally provided.
    # @!attribute [r] capabilities
    #   @return [Array<String>] list of SMART capabilities supported by the server.
    # @!attribute [r] code_challenge_methods_supported
    #   @return [Array<String>] list of PKCE code challenge methods supported. Should include "S256".
    #     Should not include "plain". See {#valid?} for compliance checks.
    class SmartMetadata < Safire::Entity
      REQUIRED_ATTRIBUTES = %i[
        grant_types_supported token_endpoint capabilities
        code_challenge_methods_supported
      ].freeze

      OPTIONAL_ATTRIBUTES = %i[
        issuer
        jwks_uri
        authorization_endpoint
        token_endpoint_auth_methods_supported
        token_endpoint_auth_signing_alg_values_supported
        registration_endpoint
        associated_endpoints
        user_access_brand_bundle
        user_access_brand_identifier
        scopes_supported
        response_types_supported
        management_endpoint
        introspection_endpoint
        revocation_endpoint
      ].freeze

      ATTRIBUTES = (REQUIRED_ATTRIBUTES | OPTIONAL_ATTRIBUTES).freeze

      # Supported asymmetric signing algorithms (required by SMART spec)
      SUPPORTED_ASYMMETRIC_ALGORITHMS = %w[RS384 ES384].freeze

      attr_reader(*ATTRIBUTES)

      def initialize(metadata)
        super(metadata, ATTRIBUTES)
      end

      # Checks whether the server's SMART metadata is valid according to SMART App Launch 2.2.0.
      #
      # This is a user-callable helper. Safire performs discovery without automatically
      # asserting server compliance — it is the caller's responsibility to invoke this
      # method when they wish to verify conformance.
      #
      # Checks performed:
      # - All required fields are present
      #   (token_endpoint, grant_types_supported, capabilities, code_challenge_methods_supported)
      # - Conditional fields present when their capability is advertised
      #   (issuer + jwks_uri for sso-openid-connect; authorization_endpoint for launch types)
      # - `code_challenge_methods_supported` includes 'S256'
      #   (SMART App Launch 2.2.0, §Conformance — SHALL be included)
      # - `code_challenge_methods_supported` does NOT include 'plain'
      #   (SMART App Launch 2.2.0, §Conformance — SHALL NOT be included)
      #
      # A warning is logged for each SMART 2.2.0 violation detected.
      #
      # @return [Boolean] true if all checks pass, false if any violation is found
      def valid?
        required_attrs = [*REQUIRED_ATTRIBUTES]
        required_attrs.push(:issuer, :jwks_uri) if issuer_and_jwks_uri_required?
        required_attrs.push(:authorization_endpoint) if authorization_endpoint_required?

        missing_attrs = required_attrs.reject { |attr| public_send(attr) }
        missing_attrs.each do |attr|
          Safire.logger.warn("SMART metadata non-compliance: required field '#{attr}' is missing")
        end

        pkce_valid = validate_pkce_methods!

        missing_attrs.empty? && pkce_valid
      end

      # Launch type support checks - requires both capability and authorization_endpoint

      def supports_ehr_launch?
        ehr_launch_capability? && authorization_endpoint.present?
      end

      def supports_standalone_launch?
        standalone_launch_capability? && authorization_endpoint.present?
      end

      # Authentication type support checks

      # Checks if the server supports public client authentication.
      # @return [Boolean] true if server has client-public capability
      def supports_public_auth?
        capability?('client-public')
      end

      # Checks if the server supports confidential symmetric authentication.
      # @return [Boolean] true if server has capability and auth methods not advertised or includes client_secret_basic
      def supports_symmetric_auth?
        capability?('client-confidential-symmetric') &&
          (token_endpoint_auth_methods_supported.blank? ||
           token_endpoint_auth_methods_supported.include?('client_secret_basic'))
      end

      # Checks if the server supports the SMART Backend Services workflow.
      # @return [Boolean] true if the server advertises the client_credentials grant type
      #   and supports private_key_jwt authentication (via {#supports_asymmetric_auth?})
      def supports_backend_services?
        grant_types_supported.present? &&
          grant_types_supported.include?('client_credentials') &&
          supports_asymmetric_auth?
      end

      # Checks if the server supports confidential asymmetric authentication.
      # @return [Boolean] true if server has capability, auth methods not advertised or includes private_key_jwt,
      #   and has supported algorithms
      def supports_asymmetric_auth?
        capability?('client-confidential-asymmetric') &&
          (token_endpoint_auth_methods_supported.blank? ||
           token_endpoint_auth_methods_supported.include?('private_key_jwt')) &&
          asymmetric_signing_algorithms_supported.any?
      end

      # Returns the asymmetric signing algorithms supported by both client and server.
      # If the server doesn't advertise algorithms, assumes it supports the required ones (RS384, ES384).
      # @return [Array<String>] list of supported algorithms
      def asymmetric_signing_algorithms_supported
        server_algs = token_endpoint_auth_signing_alg_values_supported.presence
        (server_algs || SUPPORTED_ASYMMETRIC_ALGORITHMS) & SUPPORTED_ASYMMETRIC_ALGORITHMS
      end

      # Feature support checks

      def supports_post_based_authorization?
        capability?('authorize-post')
      end

      def supports_openid_connect?
        openid_connect_capability? && issuer.present? && jwks_uri.present?
      end

      # Capability-only checks (does not verify required fields are present)

      def ehr_launch_capability?
        capability?('launch-ehr')
      end

      def standalone_launch_capability?
        capability?('launch-standalone')
      end

      def openid_connect_capability?
        capability?('sso-openid-connect')
      end

      private

      def capability?(name)
        capabilities&.include?(name)
      end

      def issuer_and_jwks_uri_required?
        openid_connect_capability?
      end

      def authorization_endpoint_required?
        ehr_launch_capability? || standalone_launch_capability?
      end

      # Validates PKCE code challenge methods per SMART App Launch 2.2.0:
      # - 'S256' SHALL be included
      # - 'plain' SHALL NOT be included
      #
      # @return [Boolean] true if both conditions are satisfied
      def validate_pkce_methods!
        methods = code_challenge_methods_supported
        valid = true

        unless methods&.include?('S256')
          Safire.logger.warn(
            "SMART metadata non-compliance: 'S256' is missing from code_challenge_methods_supported " \
            '(SMART App Launch 2.2.0 requires S256)'
          )
          valid = false
        end

        if methods&.include?('plain')
          Safire.logger.warn(
            "SMART metadata non-compliance: 'plain' is present in code_challenge_methods_supported " \
            '(SMART App Launch 2.2.0 prohibits plain)'
          )
          valid = false
        end

        valid
      end
    end
  end
end
