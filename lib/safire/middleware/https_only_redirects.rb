require 'faraday'
require 'uri'

module Safire
  module Middleware
    # Faraday middleware that blocks redirects to non-HTTPS URLs.
    #
    # Sits inside the follow_redirects middleware's app stack so it sees every
    # intermediate 3xx response before the redirect is followed. HTTP redirects
    # to localhost/127.0.0.1 are allowed (consistent with ClientConfig's
    # localhost exception for local development).
    class HttpsOnlyRedirects < Faraday::Middleware
      LOCALHOST = %w[localhost 127.0.0.1].freeze

      def call(env)
        @app.call(env).on_complete do |response_env|
          check_redirect_safety!(response_env)
        end
      end

      private

      def check_redirect_safety!(env)
        return unless (300..308).cover?(env.status)

        location = env.response_headers['location']
        return unless location

        uri = URI.parse(location)
        return if uri.scheme == 'https'
        return if LOCALHOST.include?(uri.host)

        raise Safire::Errors::NetworkError.new(
          error_description: "Redirect to non-HTTPS URL blocked: #{location}"
        )
      end
    end
  end
end
