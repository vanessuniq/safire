require 'socket'
require 'openssl'
require 'uri'
require_relative 'tls_identity'

module SafireCompliance
  # The SMART app under test: a tiny HTTPS server on loopback whose routes call Safire.
  #
  # It stands in for a web app's +/launch+ and +/callback+ routes (the Sinatra demo is not used,
  # to avoid a second process and its session store):
  #
  # * +GET /start+    — standalone launch: discovery on the configured FHIR base, then a +302+
  #   to Safire's +authorization_url+.
  # * +GET /launch+   — EHR launch: Inferno's launch link arrives with +iss+ and +launch+; the app
  #   accepts only the expected +iss+, then redirects to +authorization_url(launch:)+.
  # * +GET /callback+ — checks +state+, then calls +request_access_token+ and, when a
  #   refresh token was issued, +refresh_token+.
  #
  # Every Safire call is recorded as a local check on the current {Flow}.
  class LaunchApp
    # Per-scenario app configuration.
    #
    # +safire_config+ holds Safire client config without +base_url+/+redirect_uri+ (the app sets
    # those). +fault+ injects a negative-control fault: +:wrong_code_verifier+ or +:wrong_client_secret+.
    Flow = Struct.new(:safire_config, :client_type, :expected_iss, :checks, :redactor, :fault,
                      :expected_patient, keyword_init: true)

    attr_reader :tls, :token, :refreshed_token

    def initialize
      @tls = TLSIdentity.new
      @pending = {}
    end

    def start
      tcp = TCPServer.new('127.0.0.1', 0)
      @port = tcp.addr[1]
      @server = OpenSSL::SSL::SSLServer.new(tcp, @tls.server_context)
      @thread = Thread.new { serve }
      self
    end

    def stop
      @thread&.kill
      @server&.close
    end

    def base_url = "https://localhost:#{@port}"
    def start_url = "#{base_url}/start"
    def launch_url = "#{base_url}/launch"
    def redirect_uri = "#{base_url}/callback"

    # Resets per-scenario state.
    def prepare(flow)
      @flow = flow
      @pending = {}
      @token = nil
      @refreshed_token = nil
    end

    # @return [Hash, nil] the most recent token response (refreshed if a refresh succeeded)
    def latest_token = @refreshed_token || @token

    private

    def serve
      loop do
        conn = @server.accept
        handle(conn)
      rescue OpenSSL::SSL::SSLError, IOError, Errno::ECONNRESET
        next
      ensure
        conn&.close
      end
    end

    def handle(conn)
      path, params = read_request(conn)
      status, headers, body = route(path, params)
      write(conn, status, headers, body)
    end

    # Only GET requests without a body are served, so headers are read and discarded.
    def read_request(conn)
      request_line = conn.gets.to_s
      nil until conn.gets.to_s.strip.empty?
      uri = URI(request_line.split[1].to_s)
      [uri.path, URI.decode_www_form(uri.query.to_s).to_h]
    end

    def route(path, params)
      case path
      when '/start' then authorize(@flow.expected_iss, nil)
      when '/launch' then ehr_launch(params)
      when '/callback' then callback(params)
      else [404, {}, 'not found']
      end
    rescue StandardError => e
      [500, {}, "#{e.class}: #{@flow.redactor.call(e.message)}"]
    end

    def write(conn, status, headers, body)
      lines = ["HTTP/1.1 #{status} X", "Content-Length: #{body.bytesize}", 'Connection: close']
      headers.each { |k, v| lines << "#{k}: #{v}" }
      conn.write("#{lines.join("\r\n")}\r\n\r\n#{body}")
    end

    def ehr_launch(params)
      @flow.redactor.add(params['launch'])
      iss_ok = false
      @flow.checks.check('launch.iss_expected', 'EHR launch `iss` is the FHIR server the app trusts') do
        iss_ok = params['iss'] == @flow.expected_iss && params['launch'].to_s != ''
      end
      return [400, {}, 'unexpected iss'] unless iss_ok

      authorize(params['iss'], params['launch'])
    end

    def authorize(iss, launch)
      client = safire_client(iss)
      @flow.checks.check('discovery.smart_metadata_valid', 'SmartMetadata#valid? on Inferno discovery') do
        client.server_metadata.valid?
      end
      auth = authorization_request(client, launch)
      return [500, {}, 'authorization_url failed'] unless auth

      @flow.redactor.add(auth[:state], auth[:code_verifier])
      @pending[auth[:state]] = { client:, code_verifier: auth[:code_verifier] }
      [302, { 'Location' => auth[:auth_url] }, '']
    end

    def authorization_request(client, launch)
      auth = nil
      title = "Safire#authorization_url(launch: #{launch ? 'from EHR' : 'nil'})"
      @flow.checks.check('authorize.authorization_url', title) do
        auth = client.authorization_url(launch:)
        auth[:auth_url].start_with?(client.server_metadata.authorization_endpoint)
      end
      auth
    end

    def safire_client(iss)
      config = @flow.safire_config.merge(base_url: iss, redirect_uri:, allow_insecure_localhost: true)
      Safire::Client.new(config, client_type: @flow.client_type)
    end

    def callback(params)
      @flow.redactor.add(params['code'])
      pending = @pending.delete(params['state'])
      @flow.checks.check('callback.state_matches', 'Callback `state` matches the authorization request') do
        !pending.nil? && params['code'].to_s != ''
      end
      return [400, {}, 'state mismatch'] unless pending

      @flow.fault ? exchange_with_fault(pending, params['code']) : exchange(pending, params['code'])
      [200, { 'Content-Type' => 'text/plain' }, 'done']
    end

    def exchange(pending, code)
      client = pending[:client]
      @flow.checks.check('token.request_access_token', 'Safire#request_access_token succeeds') do
        @token = remember(client.request_access_token(code:, code_verifier: pending[:code_verifier]))
        true
      end
      return unless @token

      check_token_response('token', client, @token)
      refresh(client) if @token['refresh_token']
    end

    def check_token_response(prefix, client, token)
      @flow.checks.check("#{prefix}.token_response_valid", 'token_response_valid?(flow: :app_launch)') do
        client.token_response_valid?(token, flow: :app_launch)
      end
      @flow.checks.check("#{prefix}.patient_context", 'Token response carries the launch `patient` context') do
        token['patient'] == @flow.expected_patient
      end
    end

    def refresh(client)
      @flow.checks.check('refresh.refresh_token', 'Safire#refresh_token succeeds') do
        @refreshed_token = remember(client.refresh_token(refresh_token: @token['refresh_token']))
        true
      end
      check_token_response('refresh', client, @refreshed_token) if @refreshed_token
    end

    # Negative controls: the token request carries a PKCE verifier that does not match the
    # challenge (+:wrong_code_verifier+), or the client was configured with a client secret other
    # than the registered one (+:wrong_client_secret+). Either way Safire must surface a TokenError.
    def exchange_with_fault(pending, code)
      verifier = pending[:code_verifier]
      if @flow.fault == :wrong_code_verifier
        verifier = Safire::PKCE.generate_code_verifier
        @flow.redactor.add(verifier)
      end
      @flow.checks.expect_error("token.#{@flow.fault}_rejected",
                                "Token request with #{@flow.fault} is rejected (Safire raises TokenError)",
                                Safire::Errors::TokenError) do
        remember(pending[:client].request_access_token(code:, code_verifier: verifier))
      end
    end

    def remember(token)
      @flow.redactor.add(token.values_at('access_token', 'refresh_token', 'id_token').compact)
      token
    end
  end
end
