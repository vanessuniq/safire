require 'fileutils'
require 'json'
require 'logger'
require 'openssl'
require 'securerandom'
require 'stringio'
require 'time'

$LOAD_PATH.unshift(File.expand_path('../../lib', __dir__))
require 'safire'
require_relative 'inferno_api'
require_relative 'html_report'

module SafireCompliance
  # Phase 1 driver: SMART Backend Services against Inferno's SMART STU2.2 *client* suite.
  #
  # Inferno simulates the authorization server and FHIR server; Safire is the client.
  # The run has two kinds of checks, reported separately:
  #
  # * Inferno-driven: every result Inferno records for the session
  #   (registration, token request verification, token use).
  # * Local: Safire's own conformance helpers applied to Inferno's responses
  #   (+SmartMetadata#valid?+ on discovery, +token_response_valid?+ on the token
  #   response). These are not Inferno assertions.
  #
  # Key material is generated in memory for each run and never written to disk.
  class BackendServicesRun
    SUITE_ID = 'smart_client_stu2_2'.freeze
    CLIENT_TYPE_OPTION = { id: 'client_type', value: 'SMART,client_credentials,confidential_asymmetric' }.freeze
    SCOPES = ['system/Patient.rs'].freeze
    PATIENT_ID = 'example'.freeze
    PASSING_RESULTS = %w[pass].freeze
    # Inferno results that must be present (and pass) for the run to count as an
    # Inferno-verified pass. An empty or partial results list therefore fails.
    REQUIRED_RESULT_IDS = [
      SUITE_ID,
      "#{SUITE_ID}-smart_client_registration_bsca-smart_client_registration_bsca_verification",
      "#{SUITE_ID}-smart_client_access-smart_client_token_request_bsca_verification",
      "#{SUITE_ID}-smart_client_access-smart_client_token_use_verification"
    ].freeze
    ORCHESTRATION_ERRORS = [InfernoAPI::Error, Faraday::Error, JSON::ParserError, KeyError, TypeError].freeze

    # @param inferno_url [String] Inferno root URL (must match the host Inferno advertises)
    # @param output_dir [String] where +results.json+ and +report.html+ are written
    # @param kit_ref [String, nil] test kit commit the Inferno image was built from
    def initialize(inferno_url:, output_dir:, kit_ref: nil)
      @inferno_url = inferno_url.chomp('/')
      @output_dir = output_dir
      @kit_ref = kit_ref
      @api = InfernoAPI.new(@inferno_url)
      @client_id = "safire-#{SecureRandom.hex(6)}"
      @key = OpenSSL::PKey::RSA.generate(2048)
      @kid = SecureRandom.uuid
      @local_checks = []
      @log = StringIO.new
    end

    # Runs the flow and writes the report.
    #
    # @return [Integer] exit status: 0 when every Inferno result and every local check passed
    def call
      configure_safire_logging
      write_report(@session_id, orchestrate)
    rescue *ORCHESTRATION_ERRORS => e
      # Still write a (failed) report so the workflow uploads something to diagnose.
      @orchestration_error = "#{e.class}: #{e.message}"
      write_report(@session_id, [])
    end

    private

    def orchestrate
      @session_id = @api.create_session(SUITE_ID, [CLIENT_TYPE_OPTION]).fetch('id')
      run = @api.start_run(@session_id, SUITE_ID, inferno_inputs)
      @api.wait_for_run(run.fetch('id'), %w[waiting done])

      exercise_safire
      resume_inferno_wait
      @api.wait_for_run(run.fetch('id'), %w[done])
      @api.results(@session_id)
    end

    def configure_safire_logging
      Safire.configure do |c|
        c.logger = Logger.new(@log)
        c.log_level = Logger::WARN
        c.log_http = false
      end
    end

    def suite_base_url
      "#{@inferno_url}/custom/#{SUITE_ID}"
    end

    def fhir_base_url
      "#{suite_base_url}/fhir"
    end

    def public_jwks
      jwk = JWT::JWK.new(@key, { kid: @kid, alg: 'RS384', use: 'sig' })
      { keys: [jwk.export] }.to_json
    end

    def inferno_inputs
      [
        { name: 'client_id', value: @client_id },
        { name: 'smart_jwk_set', value: public_jwks },
        { name: 'fhir_read_resources_bundle', value: patient_bundle }
      ]
    end

    def patient_bundle
      { resourceType: 'Bundle', type: 'collection',
        entry: [{ resource: { resourceType: 'Patient', id: PATIENT_ID } }] }.to_json
    end

    def safire_client
      @safire_client ||= Safire::Client.new(
        { base_url: fhir_base_url, client_id: @client_id, private_key: @key, kid: @kid,
          scopes: SCOPES, allow_insecure_localhost: true },
        client_type: :confidential_asymmetric
      )
    end

    # Discovery gate (local) then the Backend Services token request (Inferno-verified).
    def exercise_safire
      local_check('discovery.smart_metadata_valid', 'SmartMetadata#valid? on Inferno discovery') do
        safire_client.server_metadata.valid?
      end
      @token = nil
      local_check('backend.request_backend_token', 'Safire#request_backend_token succeeds') do
        @token = safire_client.request_backend_token
        @token.is_a?(Hash)
      end
      local_check('backend.token_response_valid', 'token_response_valid?(flow: :backend_services)') do
        @token ? safire_client.token_response_valid?(@token, flow: :backend_services) : false
      end
    end

    def local_check(id, title)
      @log.truncate(0)
      @log.rewind
      passed = yield
      record_local(id, title, passed ? 'pass' : 'fail', @log.string)
    rescue Safire::Errors::Error, ArgumentError => e
      record_local(id, title, 'error', "#{e.class}: #{e.message}")
    end

    def record_local(id, title, result, detail)
      @local_checks << { id:, title:, result:, detail: detail.to_s.strip }
    end

    # The harness, not Safire, reads a resource with the issued token (Safire has no FHIR
    # client), then follows Inferno's continuation URL so the waiting test can complete.
    def resume_inferno_wait
      http = Faraday.new
      if @token&.dig('access_token')
        @fhir_read_status = http.get("#{fhir_base_url}/Patient/#{PATIENT_ID}", nil,
                                     'Authorization' => "Bearer #{@token['access_token']}").status
      end
      http.get("#{suite_base_url}/resume_pass", token: @client_id)
    end

    def write_report(session_id, results)
      report = build_report(session_id, results)
      FileUtils.mkdir_p(@output_dir)
      File.write(File.join(@output_dir, 'results.json'), JSON.pretty_generate(report))
      File.write(File.join(@output_dir, 'report.html'), HTMLReport.new(report).render)
      report[:overall] == 'pass' ? 0 : 1
    end

    def build_report(session_id, results)
      inferno = Array(results).map { |r| summarize_result(r) }
      missing = REQUIRED_RESULT_IDS - inferno.map { |r| r[:id] }
      { overall: overall_result(inferno, missing), metadata: metadata(session_id), inferno_results: inferno,
        missing_inferno_results: missing, local_checks: @local_checks,
        harness: { fhir_read_status: @fhir_read_status, orchestration_error: @orchestration_error } }
    end

    def overall_result(inferno, missing)
      return 'fail' if @orchestration_error || missing.any?

      (inferno + @local_checks).all? { |r| PASSING_RESULTS.include?(r[:result]) } ? 'pass' : 'fail'
    end

    # Input/output values (keys, tokens) are deliberately dropped; only names are kept.
    def summarize_result(result)
      { id: result['test_id'] || result['test_group_id'] || result['test_suite_id'],
        result: result['result'], result_message: result['result_message'],
        messages: result['messages'] || [],
        request_count: Array(result['requests']).size }
    end

    def metadata(session_id)
      { generated_at: Time.now.utc.iso8601, safire_version: Safire::VERSION,
        safire_commit: ENV.fetch('GITHUB_SHA', nil) || `git rev-parse HEAD 2>/dev/null`.strip,
        inferno_core_version: @api.version, test_kit_version: suite_version,
        test_kit_ref: @kit_ref, suite_id: SUITE_ID, client_type: CLIENT_TYPE_OPTION[:value],
        test_session_id: session_id }
    end

    def suite_version
      response = Faraday.get("#{@inferno_url}/api/test_suites")
      JSON.parse(response.body).find { |s| s['id'] == SUITE_ID }&.dig('version')
    rescue Faraday::Error, JSON::ParserError
      nil
    end
  end
end

if $PROGRAM_NAME == __FILE__
  exit SafireCompliance::BackendServicesRun.new(
    inferno_url: ENV.fetch('INFERNO_URL', 'http://localhost:4567'),
    output_dir: ENV.fetch('INFERNO_REPORT_DIR', File.expand_path('../../tmp/inferno', __dir__)),
    kit_ref: ENV.fetch('INFERNO_KIT_REF', nil)
  ).call
end
