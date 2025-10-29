module Safire
  module Protocols
    module Smart
      #  This class implements the SMART on FHIR Public Client OAuth2 flow as per
      #  the [SMART on FHIR specification](https://build.fhir.org/ig/HL7/smart-app-launch/app-launch.html).
      #  # @!attribute [r] client_id
      #   @return [String] the client identifier issued to the app by the authorization server
      # @!attribute [r] redirect_uri
      #   @return [String] the redirect URI registered by the app with the authorization server
      # @!attribute [r] scopes
      #   @return [Array<String>] list of OAuth2 scopes describing the app's desired access.
      #     Optionally provided.
      # @!attribute [r] issuer
      #   @return [String] the URL of the FHIR service from which the app wishes to retrieve FHIR data.
      # @!attribute [r] authorization_endpoint
      #   @return [String] URL of the server’s OAuth2 Authorization Endpoint.
      # @!attribute [r] token_endpoint
      #   @return [String] URL of the server’s OAuth2 Token Endpoint.
      class PublicClient < Entity
        ATTRIBUTES = %i[
          client_id redirect_uri scopes issuer
          authorization_endpoint token_endpoint
        ].freeze

        attr_reader(*ATTRIBUTES)

        def initialize(config)
          super(config, ATTRIBUTES)
          validate!
        end

        # This method builds the authorization URL to request an authorization code
        # @param launch [String, nil] optional launch parameter
        # @param custom_scopes [Array<String>, nil] optional custom scopes to override the configured ones
        # @return [Hash] a hash containing the authorization URL and state parameter
        #
        # @example Building authorization URL
        #   public_client = Safire::Protocols::Smart::PublicClient.new(
        #     client_id: 'my_client_id',
        #     redirect_uri: 'https://myapp.example.com/callback',
        #     scopes: ['openid', 'profile', 'patient/*.read'],
        #     issuer: 'https://fhir.example.com',
        #     authorization_endpoint: 'https://fhir.example.com/authorize',
        #     token_endpoint: 'https://fhir.example.com/token'
        #   )
        #   auth_data = public_client.authorization_url
        #   puts auth_data[:auth_url]  # The authorization URL
        #   puts auth_data[:state]     # The state parameter
        def authorization_url(launch: nil, custom_scopes: nil)
          validate_scopes_presence!(custom_scopes)

          uri = Addressable::URI.parse(authorization_endpoint)
          uri.query_values = authorization_params(launch:, custom_scopes:)

          { auth_url: uri.to_s, state: uri.query_values['state'] }
        end

        private

        def validate!
          nil_vars = ATTRIBUTES.select { |attr| send(attr).nil? }
          nil_vars.delete(:scopes)
          return if nil_vars.empty?

          raise Errors::ConfigurationError,
                "SMART Public Client configuration missing attributes: #{nil_vars.to_sentence}"
        end

        def validate_scopes_presence!(custom_scopes = nil)
          return if (scopes || custom_scopes).present?

          raise Errors::ConfigurationError,
                'SMART Public Client auth flow requires scopes (Array)'
        end

        def authorization_params(launch:, custom_scopes:)
          params = {
            response_type: 'code',
            client_id:,
            redirect_uri:,
            launch:,
            scope: [custom_scopes || scopes].flatten.join(' '),
            state: SecureRandom.hex(16),
            aud: issuer.to_s
          }.compact

          params.merge(current_pkce.auth_params)
        end

        def current_pkce
          @current_pkce ||= Safire::PKCE.new
        end
      end
    end
  end
end
