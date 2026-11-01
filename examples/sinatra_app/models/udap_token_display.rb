# frozen_string_literal: true

# Shared display helpers for the demo app's UDAP token presenters.
#
# Masks bearer credentials, labels Safire error classes, and reports the
# client signing and server trust status. Including classes must set
# +@credentials+ and +@trust_policy+ and define +error+.
module UdapTokenDisplay
  FILTERED_VALUE = '[FILTERED]'
  MASK_VISIBLE_CHARS = 4
  MASK_MIN_LENGTH = 24
  ERROR_LABELS = {
    'Safire::Errors::ConfigurationError' => 'Configuration error',
    'Safire::Errors::ValidationError' => 'Validation error',
    'Safire::Errors::DiscoveryError' => 'Discovery error',
    'Safire::Errors::CertificateError' => 'Certificate error',
    'Safire::Errors::TokenError' => 'Token error',
    'Safire::Errors::NetworkError' => 'Network error'
  }.freeze

  def credentials_configured?
    @credentials.configured?
  end

  def development_trust_mode?
    trust_policy_status.fetch(:development_mode)
  end

  def display_error
    error || trust_policy_status[:error]
  end

  def error_label
    ERROR_LABELS.fetch(display_error.class.name, 'Request failed')
  end

  def oauth_error_code
    display_error.error_code if display_error.respond_to?(:error_code)
  end

  private

  def split_list(value)
    value.to_s.split(/[,\s]+/).map(&:strip).reject(&:empty?)
  end

  # Shows only the first and last few characters of long tokens, plus the length.
  def mask(value)
    return FILTERED_VALUE unless value.is_a?(String)
    return "#{FILTERED_VALUE} (#{value.length} characters)" if value.length < MASK_MIN_LENGTH

    "#{value[0, MASK_VISIBLE_CHARS]}...#{value[-MASK_VISIBLE_CHARS..]} (#{value.length} characters)"
  end

  def trust_policy_status
    @trust_policy_status ||= { development_mode: @trust_policy.development_mode?, error: nil }
  rescue Safire::Errors::Error => e
    @trust_policy_status = { development_mode: true, error: e }
  end
end
