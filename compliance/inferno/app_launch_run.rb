require 'faraday'
require 'fileutils'
require 'json'
require 'openssl'
require 'securerandom'
require 'time'

$LOAD_PATH.unshift(File.expand_path('../../lib', __dir__))
require 'safire'
require_relative 'inferno_api'
require_relative 'redactor'
require_relative 'local_checks'
require_relative 'user_agent'
require_relative 'launch_app'
require_relative 'app_launch_html_report'

module SafireCompliance
  # Phase 2 driver: SMART App Launch (authorization code) against Inferno's STU2.2 *client* suite.
  #
  # Each scenario gets its own Inferno session, because the client type is a session-level suite
  # option. Safire acts as the client inside {LaunchApp}; {UserAgent} plays the browser. Results
  # are reported in three separate groups per scenario: Inferno-driven results, local checks of
  # Safire, and harness observations (redirect hops, FHIR read status).
  #
  # A positive scenario passes only when every expected Inferno test is present and passed, no
  # Inferno result failed, and every local check passed. A negative control passes only when the
  # targeted Inferno test is present and failed and Safire surfaced the rejection. Any
  # orchestration error fails the scenario and is recorded in the report.
  class AppLaunchRun
    SUITE_ID = 'smart_client_stu2_2'.freeze
    PATIENT_ID = 'example'.freeze

    AUTH_TYPES = {
      public: { tag: 'alp', option: 'SMART,authorization_code,public' },
      confidential_symmetric: { tag: 'alcs', option: 'SMART,authorization_code,confidential_symmetric' },
      confidential_asymmetric: { tag: 'alca', option: 'SMART,authorization_code,confidential_asymmetric' }
    }.freeze

    SCOPES = {
      standalone: %w[launch/patient offline_access patient/Patient.rs],
      ehr: %w[launch offline_access patient/Patient.rs]
    }.freeze

    SCENARIOS = [
      { id: 'standalone-public', launch: :standalone, auth: :public },
      { id: 'standalone-confidential-symmetric', launch: :standalone, auth: :confidential_symmetric },
      { id: 'standalone-confidential-asymmetric', launch: :standalone, auth: :confidential_asymmetric },
      { id: 'ehr-public', launch: :ehr, auth: :public },
      { id: 'ehr-confidential-symmetric', launch: :ehr, auth: :confidential_symmetric },
      { id: 'ehr-confidential-asymmetric', launch: :ehr, auth: :confidential_asymmetric },
      { id: 'negative-wrong-code-verifier', launch: :standalone, auth: :public,
        fault: :wrong_code_verifier, expect_fail: :token_request, expect_results: %w[fail] },
      # Test kit v1.0.3 bug: SMARTAppLaunch::AuthenticationVerification#check_authorization_header
      # interpolates an undefined `e` when the Basic header is wrong, so the verification test
      # ends in `error` (NameError) instead of `fail`. Inferno's mock token endpoint still rejects
      # the request with HTTP 401, which the local check records.
      { id: 'negative-wrong-client-secret', launch: :standalone, auth: :confidential_symmetric,
        fault: :wrong_client_secret, expect_fail: :token_request, expect_results: %w[fail error],
        note: 'Inferno test kit v1.0.3 reports `error` (NameError in check_authorization_header) ' \
              'rather than `fail` for a wrong client secret.' }
    ].freeze

    # @param inferno_url [String] Inferno root URL (must match the host Inferno advertises)
    # @param output_dir [String] where +results.json+ and +report.html+ are written
    # @param kit_ref [String, nil] test kit commit the Inferno image was built from
    # @param only [Array<String>, nil] scenario ids to run (default: all)
    def initialize(inferno_url:, output_dir:, kit_ref: nil, only: nil)
      @inferno_url = inferno_url.chomp('/')
      @output_dir = output_dir
      @kit_ref = kit_ref
      @api = InfernoAPI.new(@inferno_url)
      @scenarios = only ? SCENARIOS.select { |s| only.include?(s[:id]) } : SCENARIOS
    end

    # @return [Integer] 0 when every scenario met its expectation, 1 otherwise
    def call
      @app = LaunchApp.new.start
      results = @scenarios.map { |scenario| ScenarioRun.new(self, scenario).call }
      write_report(results)
    rescue StandardError => e
      write_report(results || [], error: "#{e.class}: #{e.message}")
    ensure
      @app&.stop
    end

    attr_reader :api, :app

    def suite_base_url = "#{@inferno_url}/custom/#{SUITE_ID}"
    def fhir_base_url = "#{suite_base_url}/fhir"

    private

    def write_report(scenarios, error: nil)
      overall = error.nil? && scenarios.any? && scenarios.all? { |s| s[:outcome] == 'pass' } ? 'pass' : 'fail'
      report = { overall:, error:, metadata:, scenarios: }
      FileUtils.mkdir_p(@output_dir)
      File.write(File.join(@output_dir, 'results.json'), JSON.pretty_generate(report))
      File.write(File.join(@output_dir, 'report.html'), AppLaunchHTMLReport.new(report).render)
      overall == 'pass' ? 0 : 1
    end

    def metadata
      { generated_at: Time.now.utc.iso8601, safire_version: Safire::VERSION,
        safire_commit: ENV.fetch('GITHUB_SHA', nil) || `git rev-parse HEAD 2>/dev/null`.strip,
        inferno_core_version: @api.version, test_kit_version: suite_version,
        test_kit_ref: @kit_ref, suite_id: SUITE_ID }
    end

    def suite_version
      response = Faraday.get("#{@inferno_url}/api/test_suites")
      JSON.parse(response.body).find { |s| s['id'] == SUITE_ID }&.dig('version')
    rescue Faraday::Error, JSON::ParserError
      nil
    end
  end

  # One scenario: one Inferno session, one launch, one evaluation.
  class ScenarioRun
    def initialize(run, scenario)
      @run = run
      @scenario = scenario
      @auth = AppLaunchRun::AUTH_TYPES.fetch(scenario[:auth])
      @client_id = "safire-#{SecureRandom.hex(6)}"
      @redactor = Redactor.new
      @checks = LocalChecks.new(@redactor)
      @harness = {}
      @credentials = build_credentials
    end

    # @return [Hash] the scenario report entry
    def call
      @checks.configure_safire_logging
      drive
      evaluate(@run.api.results(@session_id))
    rescue StandardError => e
      summary(outcome: 'error', error: @redactor.call("#{e.class}: #{e.message}"), inferno_results: [])
    end

    private

    def drive
      option = { id: 'client_type', value: @auth[:option] }
      @session_id = @run.api.create_session(AppLaunchRun::SUITE_ID, [option])['id']
      test_run = @run.api.start_run(@session_id, AppLaunchRun::SUITE_ID, inferno_inputs)
      @run.api.wait_for_run(test_run['id'], %w[waiting done])
      launch_app
      read_and_resume
      @run.api.wait_for_run(test_run['id'], %w[done])
    end

    def build_credentials
      case @scenario[:auth]
      when :confidential_symmetric
        secret = SecureRandom.alphanumeric(32)
        used = @scenario[:fault] == :wrong_client_secret ? SecureRandom.alphanumeric(32) : secret
        @redactor.add(secret, used)
        { registered: { smart_client_secret: secret }, safire: { client_secret: used } }
      when :confidential_asymmetric
        key = OpenSSL::PKey::RSA.generate(2048)
        kid = SecureRandom.uuid
        jwks = { keys: [JWT::JWK.new(key, { kid:, alg: 'RS384', use: 'sig' }).export] }.to_json
        { registered: { smart_jwk_set: jwks }, safire: { private_key: key, kid: } }
      else
        { registered: {}, safire: {} }
      end
    end

    def inferno_inputs
      inputs = { client_id: @client_id, smart_redirect_uris: @run.app.redirect_uri,
                 launch_context: { patient: AppLaunchRun::PATIENT_ID }.to_json,
                 fhir_read_resources_bundle: patient_bundle }.merge(@credentials[:registered])
      inputs[:smart_launch_urls] = @run.app.launch_url if @scenario[:launch] == :ehr
      inputs.map { |name, value| { name: name.to_s, value: } }
    end

    def patient_bundle
      { resourceType: 'Bundle', type: 'collection',
        entry: [{ resource: { resourceType: 'Patient', id: AppLaunchRun::PATIENT_ID } }] }.to_json
    end

    def launch_app
      @run.app.prepare(flow)
      agent = UserAgent.new(cert_store: @run.app.tls.cert_store)
      final = agent.navigate(entry_url)
      @harness[:user_agent_hops] = agent.hops
      @harness[:final_status] = final.code.to_i
    end

    def flow
      LaunchApp::Flow.new(
        safire_config: { client_id: @client_id, scopes: AppLaunchRun::SCOPES.fetch(@scenario[:launch]) }
                         .merge(@credentials[:safire]),
        client_type: @scenario[:auth], expected_iss: @run.fhir_base_url, checks: @checks,
        redactor: @redactor, fault: @scenario[:fault], expected_patient: AppLaunchRun::PATIENT_ID
      )
    end

    # Standalone: the user opens the app. EHR: the user opens the launch link Inferno generated
    # (session output +launch_urls+), which carries +iss+ and +launch+.
    def entry_url
      return @run.app.start_url unless @scenario[:launch] == :ehr

      url = session_value('launch_urls').to_s.split(',').first
      raise 'Inferno did not output launch_urls for the EHR launch' if url.nil?

      @redactor.add(url[/launch=([^&]+)/, 1])
      url
    end

    def session_value(name)
      @run.api.session_data(@session_id).find { |d| d['name'] == name }&.dig('value')
    end

    # Safire has no FHIR client, so the harness reads with the issued token, then follows
    # Inferno's continuation URL so the waiting test completes.
    def read_and_resume
      http = Faraday.new
      token = @run.app.latest_token&.dig('access_token')
      if token
        @harness[:fhir_read_status] = http.get("#{@run.fhir_base_url}/Patient/#{AppLaunchRun::PATIENT_ID}", nil,
                                               'Authorization' => "Bearer #{token}").status
      end
      http.get("#{@run.suite_base_url}/resume_pass", token: @client_id)
    end

    def expected_test_ids
      tag = @auth[:tag]
      access = "#{AppLaunchRun::SUITE_ID}-smart_client_access"
      { registration: "#{AppLaunchRun::SUITE_ID}-smart_client_registration_#{tag}-" \
                      "smart_client_registration_#{tag}_verification",
        interaction: "#{access}-smart_client_access_#{tag}_interaction",
        authorization_request: "#{access}-smart_client_authorization_request_#{tag}_verification",
        token_request: "#{access}-smart_client_token_request_#{tag}_verification",
        token_use: "#{access}-smart_client_token_use_verification" }
    end

    def evaluate(raw_results)
      inferno = raw_results.map { |r| summarize_result(r) }
      by_id = inferno.to_h { |r| [r[:id], r[:result]] }
      outcome, reasons = @scenario[:expect_fail] ? judge_negative(by_id) : judge_positive(inferno, by_id)
      summary(outcome:, reasons:, inferno_results: inferno)
    end

    # Every expected test and the suite must be present and +pass+ (an empty or partial result
    # set fails), and no other result may be anything but +pass+.
    def judge_positive(inferno, by_id)
      required = expected_test_ids.values + [AppLaunchRun::SUITE_ID]
      reasons = required.filter_map { |id| unexpected(id, by_id[id], %w[pass]) }
      reasons += inferno.reject { |r| r[:result] == 'pass' }.map { |r| "#{r[:id]}: #{r[:result]}" }
      verdict(reasons + failed_local_checks)
    end

    def unexpected(id, result, allowed)
      return if allowed.include?(result)

      "expected Inferno result #{id} to be #{allowed.join('/')}, got #{result || 'no result'}"
    end

    def judge_negative(by_id)
      target = expected_test_ids.fetch(@scenario[:expect_fail])
      verdict([unexpected(target, by_id[target], @scenario[:expect_results])].compact + failed_local_checks)
    end

    def verdict(reasons) = [reasons.empty? ? 'pass' : 'fail', reasons.uniq]

    def failed_local_checks
      @checks.entries.reject { |c| c[:result] == 'pass' }.map { |c| "local check #{c[:id]}: #{c[:result]}" }
    end

    # Input/output values (keys, tokens) are dropped; messages are redacted.
    def summarize_result(result)
      { id: result['test_id'] || result['test_group_id'] || result['test_suite_id'],
        result: result['result'], result_message: @redactor.call(result['result_message']),
        messages: Array(result['messages']).map { |m| redact_message(m) },
        request_count: Array(result['requests']).size }
    end

    def redact_message(message)
      { 'type' => message['type'], 'message' => @redactor.call(message['message']) }
    end

    def expected_summary
      if @scenario[:expect_fail]
        { @scenario[:expect_results].join('/') => [expected_test_ids[@scenario[:expect_fail]]] }
      else
        { 'pass' => expected_test_ids.values + [AppLaunchRun::SUITE_ID] }
      end
    end

    def summary(outcome:, inferno_results:, reasons: [], error: nil)
      { id: @scenario[:id], kind: @scenario[:expect_fail] ? 'negative control' : 'positive',
        launch: @scenario[:launch].to_s, client_type: @auth[:option], fault: @scenario[:fault]&.to_s,
        expected: expected_summary, note: @scenario[:note],
        test_session_id: @session_id, outcome:, reasons:, error:, inferno_results:,
        local_checks: @checks.entries, harness: @harness }
    end
  end
end

if $PROGRAM_NAME == __FILE__
  exit SafireCompliance::AppLaunchRun.new(
    inferno_url: ENV.fetch('INFERNO_URL', 'http://localhost:4567'),
    output_dir: ENV.fetch('INFERNO_APP_LAUNCH_REPORT_DIR', File.expand_path('../../tmp/inferno/app-launch', __dir__)),
    kit_ref: ENV.fetch('INFERNO_KIT_REF', nil),
    only: ENV['INFERNO_SCENARIOS']&.split(',')
  ).call
end
