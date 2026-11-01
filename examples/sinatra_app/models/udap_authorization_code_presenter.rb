# frozen_string_literal: true

require_relative 'udap_token_display'

# Presentation model for the demo app's UDAP authorization code workflow.
#
# Prefills the start form from the server's stored UDAP registration, carries
# the optional Tiered OAuth preferred IdP (UDAP STU2 user.md §6.1), reports
# authorization-response errors returned to the callback (including the Tiered
# OAuth +invalid_idp+ error, STU2 §6.2), and prepares token
# responses for display without rendering bearer credentials: the access token
# is masked, and the refresh token, ID token, and any unknown field are
# replaced with +[FILTERED]+.
class UdapAuthorizationCodePresenter
  include UdapTokenDisplay

  DISPLAYABLE_RESPONSE_FIELDS = %w[token_type expires_in scope patient encounter].freeze
  private_constant :DISPLAYABLE_RESPONSE_FIELDS

  # Extension error code a data holder returns when it rejects the requested IdP (STU2 §6.2).
  INVALID_IDP_ERROR = 'invalid_idp'

  attr_reader :server, :redirect_uri, :token_response, :error, :authorization_error, :result_kind

  # @param authorization_error [Hash, nil] +error+ and +error_description+ from the
  #   authorization response (RFC 6749 §4.1.2.1), after the callback state matched
  # @param result_kind [Symbol, nil] +:exchange+ or +:refresh+ for a token result
  # @param refresh_available [Boolean] whether the session holds a refresh token for this server
  def initialize(server:, params:, credentials:, trust_policy:, redirect_uri:, token_response: nil, error: nil,
                 authorization_error: nil, result_kind: nil, refresh_available: false)
    @server = server
    @params = params || {}
    @credentials = credentials
    @trust_policy = trust_policy
    @redirect_uri = redirect_uri
    @token_response = token_response
    @error = error
    @authorization_error = authorization_error
    @result_kind = result_kind
    @refresh_available = refresh_available
  end

  def success?
    token_response.present?
  end

  def refresh_available?
    @refresh_available
  end

  def client_id
    return param('client_id').to_s.strip if param_supplied?('client_id')

    server.udap_client_id.to_s
  end

  def scope
    return param('scope').to_s if param_supplied?('scope')

    server.udap_scope.presence || server.scopes.join(' ')
  end

  def community
    return param('community').to_s.strip if param_supplied?('community')

    server.udap_community.to_s
  end

  # Preferred IdP base URL for Tiered OAuth, as entered (surrounding whitespace removed).
  # Never prefilled: Tiered OAuth is opt-in per request.
  def idp
    param('idp').to_s.strip
  end

  # @return [String, nil] the IdP to pass as +idp:+, or nil (no Tiered OAuth) when blank
  def tiered_oauth_idp
    idp.presence
  end

  # @return [Boolean] whether the data holder rejected the requested IdP (STU2 §6.2)
  def invalid_idp?
    authorization_error&.[](:error) == INVALID_IDP_ERROR
  end

  # @return [Array<String>] requested scopes split on commas and whitespace
  def scopes
    split_list(scope)
  end

  def masked_access_token
    mask(token_response&.[]('access_token'))
  end

  def refresh_token_issued?
    token_response&.[]('refresh_token').is_a?(String)
  end

  def granted_scopes
    value = token_response&.[]('scope')
    value.is_a?(String) ? value.split : []
  end

  def safe_token_response
    (token_response || {}).to_h do |key, value|
      key = key.to_s
      [key, display_value(key, value)]
    end
  end

  private

  def param(name)
    @params[name] || @params[name.to_sym]
  end

  def param_supplied?(name)
    @params.key?(name) || @params.key?(name.to_sym)
  end

  def display_value(key, value)
    return mask(value) if key == 'access_token'
    return FILTERED_VALUE unless DISPLAYABLE_RESPONSE_FIELDS.include?(key)

    value.is_a?(String) || value.is_a?(Numeric) ? value : FILTERED_VALUE
  end
end
