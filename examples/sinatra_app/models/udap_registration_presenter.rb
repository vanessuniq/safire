# frozen_string_literal: true

require 'pathname'

# Presentation model for the demo app's UDAP Dynamic Client Registration flow.
class UdapRegistrationPresenter
  GRANT_TYPES = %w[client_credentials authorization_code].freeze
  SENSITIVE_RESPONSE_FIELDS = %w[
    software_statement
    certifications
    private_key
    certificate_chain
    certificate
    certificates
    x5c
    client_secret
  ].freeze
  FILTERED_VALUE = '[FILTERED]'
  DEFAULT_CLIENT_NAME = 'Safire Demo App'
  DEFAULT_CONTACTS = 'mailto:admin@example.com'
  DEFAULT_SCOPE = 'system/*.rs'
  DEMO_LOGO_PATH = '/safire-demo-logo.png'
  CERTIFICATIONS_FILE_ENV = 'UDAP_CLIENT_CERTIFICATIONS_FILE'
  APP_ROOT = File.expand_path('..', __dir__)

  private_constant :GRANT_TYPES, :SENSITIVE_RESPONSE_FIELDS, :FILTERED_VALUE,
                   :DEFAULT_CLIENT_NAME, :DEFAULT_CONTACTS, :DEFAULT_SCOPE,
                   :DEMO_LOGO_PATH, :CERTIFICATIONS_FILE_ENV, :APP_ROOT

  attr_reader :server, :registration_response, :cancellation_response,
              :expected_client_id, :error

  def initialize(server:, params:, credentials:, trust_policy:, client_uri:, redirect_uri:,
                 registration_response: nil, cancellation_response: nil,
                 expected_client_id: nil, error: nil, env: ENV)
    @server = server
    @params = params || {}
    @credentials = credentials
    @trust_policy = trust_policy
    @default_client_uri = client_uri
    @default_redirect_uri = redirect_uri
    @registration_response = registration_response
    @cancellation_response = cancellation_response
    @expected_client_id = expected_client_id
    @error = error
    @env = env
  end

  def credentials_configured?
    @credentials.configured?
  end

  def development_trust_mode?
    trust_policy_status.fetch(:development_mode)
  end

  def display_error
    error || trust_policy_status[:error] || certifications_status[:error]
  end

  def grant_type
    value = param('grant_type').presence
    GRANT_TYPES.include?(value) ? value : 'client_credentials'
  end

  def authorization_code?
    grant_type == 'authorization_code'
  end

  def client_uri
    param('client_uri').presence || @default_client_uri
  end

  def client_name
    param('client_name').presence ||
      env_value('UDAP_CLIENT_NAME') ||
      env_value('CLIENT_NAME') ||
      DEFAULT_CLIENT_NAME
  end

  def contacts_value
    param('contacts').presence || env_value('UDAP_CLIENT_CONTACTS') || DEFAULT_CONTACTS
  end

  def certifications_value
    certifications_status[:value].to_s
  end

  def scope
    param('scope').presence || server.scopes.join(' ').presence || DEFAULT_SCOPE
  end

  def community
    param('community').presence.to_s
  end

  def redirect_uris_value
    param('redirect_uris').presence || @default_redirect_uri
  end

  def logo_uri
    param('logo_uri').presence || env_value('UDAP_CLIENT_LOGO_URI') || "#{client_uri}#{DEMO_LOGO_PATH}"
  end

  def response_types_value
    'code'
  end

  def registered_client_id
    safe_response_value(registration_response, 'client_id')
  end

  def cancellation_client_id
    safe_response_value(cancellation_response, 'client_id')
  end

  def registration_success?
    registration_response.present?
  end

  def cancellation_result?
    cancellation_response.present?
  end

  def cancellation_context_configured?
    server.udap_client_uri.present?
  end

  def cancellation_confirmed?
    cancellation_response&.fetch('grant_types', nil).is_a?(Array) &&
      cancellation_response['grant_types'].empty?
  end

  def cancellation_mismatch?
    cancellation_confirmed? &&
      expected_client_id.present? &&
      cancellation_client_id.present? &&
      cancellation_client_id != expected_client_id
  end

  def safe_registration_response
    filter_sensitive_response(registration_response || {})
  end

  def safe_cancellation_response
    filter_sensitive_response(cancellation_response || {})
  end

  private

  def param(name)
    @params[name] || @params[name.to_sym]
  end

  def env_value(name)
    @env.fetch(name, nil).to_s.strip.presence
  end

  def certifications_status
    @certifications_status ||= begin
      value = param('certifications').presence
      value ||= certifications_file_value
      { value:, error: nil }
    rescue Errno::EACCES, Errno::ENOENT, Errno::ENOTDIR
      {
        value: nil,
        error: Safire::Errors::ConfigurationError.new(
          invalid_attribute: CERTIFICATIONS_FILE_ENV.to_sym,
          invalid_value: env_value(CERTIFICATIONS_FILE_ENV),
          valid_values: ['readable file path']
        )
      }
    end
  end

  def certifications_file_value
    path = env_value(CERTIFICATIONS_FILE_ENV)
    return unless path

    File.read(expand_certifications_path(path)).strip.presence
  end

  def expand_certifications_path(path)
    return path if Pathname.new(path).absolute?

    File.expand_path(path, APP_ROOT)
  end

  def safe_response_value(response, key)
    value = response&.[](key)
    value.is_a?(String) ? value : nil
  end

  def filter_sensitive_response(value)
    case value
    when Hash
      value.to_h do |key, entry|
        key = key.to_s
        [key, sensitive_response_field?(key) ? FILTERED_VALUE : filter_sensitive_response(entry)]
      end
    when Array
      value.map { |entry| filter_sensitive_response(entry) }
    else
      value
    end
  end

  def sensitive_response_field?(key)
    SENSITIVE_RESPONSE_FIELDS.include?(key)
  end

  def trust_policy_status
    @trust_policy_status ||= {
      development_mode: @trust_policy.development_mode?,
      error: nil
    }
  rescue Safire::Errors::Error => e
    @trust_policy_status = { development_mode: true, error: e }
  end
end
