require 'net/http'
require 'uri'

module SafireCompliance
  # A minimal browser stand-in that follows HTTP redirects across hosts.
  #
  # Inferno's simulated authorization endpoint answers an authorization request with an
  # immediate +302+ to the client's +redirect_uri+: it renders no login or consent page, sets no
  # cookies, and runs no JavaScript. Following +Location+ headers therefore produces exactly the
  # requests a browser would make. Each hop is recorded as host, path, and status only; query
  # strings (which carry +code+, +state+, and +launch+) are not recorded.
  class UserAgent
    class Error < StandardError; end

    MAX_HOPS = 10

    attr_reader :hops

    # @param cert_store [OpenSSL::X509::Store] trust store for +https+ hops (the harness app's certificate)
    def initialize(cert_store:)
      @cert_store = cert_store
      @hops = []
    end

    # Navigates to +url+ and follows redirects until a non-redirect response.
    #
    # @return [Net::HTTPResponse] the final response
    # @raise [Error] if more than {MAX_HOPS} redirects are followed
    def navigate(url)
      uri = URI(url)
      MAX_HOPS.times do
        response = get(uri)
        @hops << { url: "#{uri.scheme}://#{uri.host}:#{uri.port}#{uri.path}", status: response.code.to_i }
        return response unless response.is_a?(Net::HTTPRedirection)

        uri = URI.join(uri.to_s, response['location'])
      end
      raise Error, "more than #{MAX_HOPS} redirects"
    end

    private

    def get(uri)
      http = Net::HTTP.new(uri.host, uri.port, nil) # loopback only: never use a proxy
      http.open_timeout = 10
      http.read_timeout = 60
      if uri.scheme == 'https'
        http.use_ssl = true
        http.cert_store = @cert_store
        http.verify_mode = OpenSSL::SSL::VERIFY_PEER
      end
      http.start { |conn| conn.get(uri.request_uri) }
    end
  end
end
