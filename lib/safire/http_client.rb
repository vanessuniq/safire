require 'active_support/all'
require 'faraday'
require 'faraday/follow_redirects'

module Safire
  # HTTP client wrapper for Safire
  class HTTPClient
    def initialize(base_url: nil, adapter: nil, request_format: :url_encoded, ssl_options: {})
      @options = {
        url: normalize_base_url(base_url),
        ssl: ssl_options,
        headers: { 'User-Agent' => "Safire v#{Safire::VERSION}", 'Accept' => 'application/json' }
      }
      @adapter = adapter || Faraday.default_adapter
      @request_format = request_format.to_sym
      warn_if_ssl_verification_disabled(ssl_options)
      @connection = build_connection
    end

    def get(path = '', params: {}, headers: {})
      request(:get, path, params:, headers:)
    end

    def post(path = '', body: nil, params: {}, headers: {})
      request(:post, path, body:, params:, headers:)
    end

    def put(path = '', body: nil, params: {}, headers: {})
      request(:put, path, body:, params:, headers:)
    end

    def delete(path = '', params: {}, headers: {})
      request(:delete, path, params:, headers:)
    end

    private

    def build_connection
      Faraday.new(@options) do |builder|
        builder.request @request_format
        builder.response :follow_redirects
        builder.response :json
        builder.response :raise_error
        configure_logger(builder)
        builder.adapter @adapter
      end
    end

    def configure_logger(builder)
      return if Safire.configuration&.log_http == false

      builder.response :logger, Safire.logger, { headers: { request: true, response: true }, bodies: false } do |logger|
        logger.filter(/(Authorization: )(.+)/, '\1[FILTERED]')
      end
    end

    def request(method, path, body: nil, params: {}, headers: {})
      @connection.send(method) do |req|
        req.url path.sub(%r{^/}, '') # Remove leading slash if present since base_url ends with slash
        req.params.update(params) if params.present?
        req.headers.update(headers) if headers.present?
        req.body = body if body
      end
    rescue Faraday::ConnectionFailed, Faraday::TimeoutError, Faraday::SSLError => e
      raise Safire::Errors::NetworkError.new(error_description: e.message)
    end

    def warn_if_ssl_verification_disabled(ssl_options)
      return unless ssl_options[:verify] == false

      Safire.logger.warn(
        '[Safire] ssl_options: { verify: false } disables TLS certificate verification — ' \
        'do not use in production'
      )
    end

    def normalize_base_url(url)
      return '' unless url

      url.ends_with?('/') ? url : "#{url}/"
    end
  end
end
