module Safire
  module Client
    module Protocols
      module Smart
        class SmartMetadata < Safire::Client::Entity
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
end
