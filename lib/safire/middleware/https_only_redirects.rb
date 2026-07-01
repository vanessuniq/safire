require 'faraday'
require 'uri'
require_relative '../uri_validation'

module Safire
  module Middleware
    # Faraday middleware that blocks redirects to non-HTTPS URLs.
    #
    # Sits inside the follow_redirects middleware's app stack so it sees every
    # intermediate 3xx response before the redirect is followed. HTTP redirects
    # to localhost/127.0.0.1 are allowed only when the caller explicitly enables
    # the local-development exception.
    class HttpsOnlyRedirects < Faraday::Middleware
      include URIValidation

      def initialize(app, allow_insecure_localhost: false)
        super(app)
        @allow_insecure_localhost = validate_localhost_policy(allow_insecure_localhost)
      end

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
        return if @allow_insecure_localhost && localhost_host?(uri.host)

        raise Safire::Errors::NetworkError.new(
          error_description: "Redirect to non-HTTPS URL blocked: #{location}"
        )
      end
    end
  end
end
