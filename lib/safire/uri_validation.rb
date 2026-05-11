module Safire
  # Shared URI classification for HTTPS enforcement.
  #
  # Provides {#classify_uri} and {#localhost_host?} as private instance methods.
  # Include this module in any class that must validate URIs against the project's
  # HTTPS-only policy (SMART App Launch 2.2.0 §App Protection).
  #
  # @api private
  module URIValidation
    private

    # Classifies a URI value as +:invalid+, +:non_https+, or +nil+ (acceptable).
    #
    # HTTPS is accepted for all hosts. Plain HTTP is accepted only for localhost
    # and 127.0.0.1 to support development without TLS. Any other scheme
    # (including non-HTTP schemes on localhost) returns +:non_https+.
    #
    # @param value [String, nil] the URI string to classify
    # @return [:invalid, :non_https, nil]
    def classify_uri(value)
      uri = Addressable::URI.parse(value)
      return :invalid unless uri.scheme && uri.host
      return if uri.scheme == 'https'
      return if uri.scheme == 'http' && localhost_host?(uri.host)

      :non_https
    rescue Addressable::URI::InvalidURIError
      :invalid
    end

    # Returns +true+ when the host is a local loopback address.
    #
    # @param host [String] the URI host
    # @return [Boolean]
    def localhost_host?(host)
      %w[localhost 127.0.0.1].include?(host)
    end
  end
end
