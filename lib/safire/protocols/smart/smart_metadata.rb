module Safire
  module Protocols
    module Smart
      class SmartMetadata < Safire::Entity
        # Attributes available in SMART discovery response as per [SMART on FHIR specification](https://build.fhir.org/ig/HL7/smart-app-launch/conformance.html#using-well-known)
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
        #   @return [Array<String>] list of PKCE code challenge methods supported. Must include "S256".
        #     Must not include "plain".
        ATTRIBUTES = %i[
          issuer jwks_uri authorization_endpoint grant_types_supported
          token_endpoint token_endpoint_auth_methods_supported registration_endpoint
          associated_endpoints user_access_brand_bundle user_access_brand_identifier
          scopes_supported response_types_supported management_endpoint introspection_endpoint
          revocation_endpoint capabilities code_challenge_methods_supported
        ].freeze

        attr_reader(*ATTRIBUTES)

        def initialize(metadata)
          super(metadata, ATTRIBUTES)
        end
      end
    end
  end
end
