require 'spec_helper'
require 'tmpdir'
require_relative '../../compliance/inferno/app_launch_run'

# Unit coverage for the Phase 2 report decision. The launch itself (Safire calls, user agent,
# HTTPS app) is exercised against a real Inferno only, so those steps are stubbed here.
RSpec.describe SafireCompliance::AppLaunchRun do
  let(:api) { instance_double(SafireCompliance::InfernoAPI, version: '1.4.3') }
  let(:app) { instance_double(SafireCompliance::LaunchApp, stop: nil) }
  let(:output_dir) { Dir.mktmpdir }
  let(:report) { JSON.parse(File.read(File.join(output_dir, 'results.json'))) }
  let(:suite) { described_class::SUITE_ID }
  let(:alp_ids) do
    access = "#{suite}-smart_client_access"
    ["#{suite}-smart_client_registration_alp-smart_client_registration_alp_verification",
     "#{access}-smart_client_access_alp_interaction",
     "#{access}-smart_client_authorization_request_alp_verification",
     "#{access}-smart_client_token_request_alp_verification",
     "#{access}-smart_client_token_use_verification"]
  end

  before do
    allow(SafireCompliance::InfernoAPI).to receive(:new).and_return(api)
    allow(SafireCompliance::LaunchApp).to receive(:new).and_return(app)
    allow(app).to receive(:start).and_return(app)
    allow(Faraday).to receive(:get).and_raise(Faraday::ConnectionFailed, 'no suites endpoint in unit test')
  end

  # The driver routes Safire logging into a per-scenario buffer; restore the global config.
  around do |example|
    saved = Safire.configuration&.dup
    example.run
  ensure
    Safire.instance_variable_set(:@configuration, saved)
  end

  after { FileUtils.remove_entry(output_dir) }

  def run_scenarios(*ids)
    described_class.new(inferno_url: 'http://inferno.test', output_dir:, only: ids).call
  end

  def result(id, value = 'pass')
    { 'test_id' => id, 'result' => value }
  end

  def stub_scenario(results, &block)
    allow(api).to receive(:results).and_return(results)
    allow_any_instance_of(SafireCompliance::ScenarioRun).to receive(:drive) do |scenario_run| # rubocop:disable RSpec/AnyInstance
      block&.call(scenario_run.instance_variable_get(:@checks))
    end
  end

  def scenario
    report['scenarios'].first
  end

  describe 'positive scenario' do
    it 'fails when Inferno returns no results' do
      stub_scenario([])

      expect(run_scenarios('standalone-public')).to eq(1)
      expect(scenario['outcome']).to eq('fail')
      expect(scenario['reasons'].size).to eq(alp_ids.size + 1)
    end

    it 'fails when only some expected results are present, even if they pass' do
      stub_scenario([result(suite)])

      expect(run_scenarios('standalone-public')).to eq(1)
      expect(scenario['reasons'].join).to include('token_request_alp_verification')
    end

    it 'fails when an unexpected Inferno result is not pass' do
      stub_scenario((alp_ids + [suite]).map { |id| result(id) } + [result("#{suite}-other", 'skip')])

      expect(run_scenarios('standalone-public')).to eq(1)
      expect(scenario['reasons']).to include("#{suite}-other: skip")
    end

    it 'fails when a local check fails' do
      stub_scenario((alp_ids + [suite]).map { |id| result(id) }) { |checks| checks.check('x', 'x') { false } }

      expect(run_scenarios('standalone-public')).to eq(1)
      expect(scenario['reasons']).to include('local check x: fail')
    end

    it 'passes when every expected result is present and passing' do
      stub_scenario((alp_ids + [suite]).map { |id| result(id) })

      expect(run_scenarios('standalone-public')).to eq(0)
      expect(report['overall']).to eq('pass')
    end
  end

  describe 'negative control' do
    let(:token_request) { alp_ids[3] }

    it 'passes when the target test fails and Safire recorded the rejection' do
      stub_scenario([result(token_request, 'fail')]) do |checks|
        checks.check('token.wrong_code_verifier_rejected', 'rejected') { true }
      end

      expect(run_scenarios('negative-wrong-code-verifier')).to eq(0)
    end

    it 'fails when the target test passes' do
      stub_scenario([result(token_request)]) do |checks|
        checks.check('token.wrong_code_verifier_rejected', 'rejected') { true }
      end

      expect(run_scenarios('negative-wrong-code-verifier')).to eq(1)
    end

    it 'fails when the rejection check was never recorded' do
      stub_scenario([result(token_request, 'fail')])

      expect(run_scenarios('negative-wrong-code-verifier')).to eq(1)
      expect(scenario['reasons'].join).to include('was not recorded')
    end
  end

  describe 'orchestration failures' do
    it 'records an unreachable Inferno as a scenario error and writes a failed report' do
      allow(api).to receive(:create_session).and_raise(Faraday::ConnectionFailed, 'connection refused')

      expect(run_scenarios('standalone-public')).to eq(1)
      expect(scenario['outcome']).to eq('error')
      expect(scenario['error']).to include('ConnectionFailed')
      expect(File).to exist(File.join(output_dir, 'report.html'))
    end

    it 'writes a failed report when the app cannot start' do
      allow(app).to receive(:start).and_raise(Errno::EADDRINUSE)

      expect(run_scenarios('standalone-public')).to eq(1)
      expect(report['error']).to include('EADDRINUSE')
    end

    it 'fails when no scenario ran' do
      expect(run_scenarios('no-such-scenario')).to eq(1)
      expect(report['overall']).to eq('fail')
    end
  end
end
