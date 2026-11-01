# frozen_string_literal: true

require_relative 'udap_token_display'

# Presentation model for the demo app's UDAP B2B client_credentials token flow.
#
# Builds the +hl7-b2b+ Authorization Extension Object from form input and
# prepares token responses for display without rendering bearer credentials.
# Input validation is left to Safire so the page shows the library's own
# ValidationError messages.
class UdapB2bTokenPresenter
  include UdapTokenDisplay

  B2B_STRING_FIELDS = %w[organization_id organization_name subject_name subject_id subject_role].freeze
  B2B_LIST_FIELDS = %w[purpose_of_use consent_policy consent_reference].freeze
  DISPLAYABLE_RESPONSE_FIELDS = %w[token_type expires_in scope].freeze

  private_constant :B2B_STRING_FIELDS, :B2B_LIST_FIELDS, :DISPLAYABLE_RESPONSE_FIELDS

  attr_reader :server, :token_response, :error

  def initialize(server:, params:, credentials:, trust_policy:, token_response: nil, error: nil)
    @server = server
    @params = params || {}
    @credentials = credentials
    @trust_policy = trust_policy
    @token_response = token_response
    @error = error
  end

  def success?
    token_response.present?
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

  def field_value(name)
    param(name).to_s
  end

  # @return [Array<String>] requested scopes split on commas and whitespace
  def scopes
    split_list(scope)
  end

  # @return [Hash{String => String, Array<String>}] hl7-b2b members with blank inputs omitted
  def b2b
    strings = B2B_STRING_FIELDS.filter_map { |name| [name, param(name).to_s.strip] if param(name).present? }
    lists = B2B_LIST_FIELDS.filter_map do |name|
      values = split_list(param(name))
      [name, values] unless values.empty?
    end
    (strings + lists).to_h
  end

  def masked_access_token
    mask(token_response&.[]('access_token'))
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
