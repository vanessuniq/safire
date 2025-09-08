require 'faraday'

module Safire
  # HTTP client wrapper for Safire
  class HTTPClient
    def initialize(base_url: nil, adapter: nil, request_format: :url_encoded, ssl_options: {})
      @options = {
        url: base_url,
        ssl: ssl_options,
        headers: { 'User-Agent' => "Safire v#{Safire::VERSION}", 'Accept' => 'application/json' }
      }
      @adapter = adapter || Faraday.default_adapter
      @request_format = request_format.to_sym
      @connection = build_connection
    end

    def get(path, params: {}, headers: {})
      request(:get, path, params:, headers:)
    end

    def post(path, body: nil, params: {}, headers: {})
      request(:post, path, body:, params:, headers:)
    end

    def put(path, body: nil, params: {}, headers: {})
      request(:put, path, body:, params:, headers:)
    end

    def delete(path, params: {}, headers: {})
      request(:delete, path, params:, headers:)
    end

    private

    def build_connection
      Faraday.new(@options) do |conn|
        conn.request @request_format
        conn.response :follow_redirects
        conn.response :json, content_type: /\bjson$/
        builder.response :raise_error
        builder.response :logger
        conn.adapter @adapter
      end
    end

    def request(method, path, body: nil, params: {}, headers: {}) # rubocop:disable Metrics/AbcSize
      @connection.send(method, path) do |req|
        req.params.update(params) if params.present?
        req.headers.update(headers) if headers.present?
        req.body = body if body
      end
    rescue Faraday::Error, Faraday::ConnectionFailed, Faraday::TimeoutError, Faraday::SSLError => e
      raise Safire::Errors::NetworkError.new(
        "HTTP request failed: #{e.message}",
        details: { status: e.response&.dig(:status), body: safe_body(e.response&.dig(:body)) }
      )
    end

    def safe_body(body)
      return body unless body.is_a?(String) && body.length > 2000

      "#{body[0..2000]}... (truncated, total #{body.length} characters)"
    end
  end
end
