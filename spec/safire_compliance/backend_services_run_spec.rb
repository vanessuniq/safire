require 'spec_helper'
require 'tmpdir'
require_relative '../../compliance/inferno/backend_services_run'

RSpec.describe SafireCompliance::BackendServicesRun do
  subject(:run) { described_class.new(inferno_url: 'http://inferno.test', output_dir:) }

  let(:output_dir) { Dir.mktmpdir }
  let(:api) { instance_double(SafireCompliance::InfernoAPI, version: '1.4.3') }
  let(:report) { JSON.parse(File.read(File.join(output_dir, 'results.json'))) }

  before do
    allow(SafireCompliance::InfernoAPI).to receive(:new).and_return(api)
    allow(Faraday).to receive(:get).and_raise(Faraday::ConnectionFailed, 'no suites endpoint in unit test')
  end

  after { FileUtils.remove_entry(output_dir) }

  def passing(id)
    { 'test_id' => id, 'result' => 'pass' }
  end

  def stub_orchestration(results)
    allow(api).to receive_messages(create_session: { 'id' => 'session-1' }, start_run: { 'id' => 'run-1' },
                                   wait_for_run: { 'status' => 'done' }, results:)
    # The Safire client calls and the FHIR read are exercised against real Inferno only;
    # these unit examples cover the report decision, so those steps are stubbed.
    allow(run).to receive(:exercise_safire) # rubocop:disable RSpec/SubjectStub
    allow(run).to receive(:resume_inferno_wait) # rubocop:disable RSpec/SubjectStub
  end

  it 'fails when Inferno returns no results' do
    stub_orchestration([])

    expect(run.call).to eq(1)
    expect(report['overall']).to eq('fail')
    expect(report['missing_inferno_results']).to match_array(described_class::REQUIRED_RESULT_IDS)
  end

  it 'fails when only some required Inferno results are present, even if they pass' do
    stub_orchestration([passing(described_class::SUITE_ID)])

    expect(run.call).to eq(1)
    expect(report['missing_inferno_results']).not_to include(described_class::SUITE_ID)
    expect(report['missing_inferno_results'].size).to eq(described_class::REQUIRED_RESULT_IDS.size - 1)
  end

  it 'passes only when every required Inferno result is present and passing' do
    stub_orchestration(described_class::REQUIRED_RESULT_IDS.map { |id| passing(id) })

    expect(run.call).to eq(0)
    expect(report['overall']).to eq('pass')
    expect(report['metadata']['test_session_id']).to eq('session-1')
  end

  it 'writes a failed report when polling times out' do
    stub_orchestration([])
    allow(api).to receive(:wait_for_run).and_raise(SafireCompliance::InfernoAPI::Error, 'test run run-1 stuck')

    expect(run.call).to eq(1)
    expect(report['harness']['orchestration_error']).to include('stuck')
    expect(File).to exist(File.join(output_dir, 'report.html'))
  end

  it 'writes a failed report when Inferno is unreachable' do
    allow(api).to receive(:create_session).and_raise(Faraday::ConnectionFailed, 'connection refused')

    expect(run.call).to eq(1)
    expect(report['overall']).to eq('fail')
    expect(report['harness']['orchestration_error']).to include('ConnectionFailed')
    expect(File.read(File.join(output_dir, 'report.html'))).to include('Orchestration error')
  end
end
