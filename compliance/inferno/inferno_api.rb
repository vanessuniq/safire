require 'faraday'
require 'json'

module SafireCompliance
  # Minimal client for the Inferno JSON API (inferno_core 1.x, +/api+ routes).
  #
  # Only the endpoints the harness needs are wrapped: version lookup, test
  # session creation, starting a suite run, polling the run, reading session
  # data, and retrieving session results.
  class InfernoAPI
    class Error < StandardError; end

    attr_reader :base_url

    # @param base_url [String] Inferno root URL, e.g. +http://localhost:4567+
    def initialize(base_url)
      @base_url = base_url.chomp('/')
      @http = Faraday.new(url: @base_url) do |f|
        f.options.timeout = 60
        f.options.open_timeout = 10
      end
    end

    # @return [String, nil] inferno_core version, or nil when Inferno is not reachable
    def version
      response = @http.get('/api/version')
      response.success? ? JSON.parse(response.body)['version'] : nil
    rescue Faraday::Error, JSON::ParserError
      nil
    end

    # @return [Hash] the created test session (includes the suite tree)
    def create_session(suite_id, suite_options)
      post('/api/test_sessions', test_suite_id: suite_id, suite_options:)
    end

    # @return [Hash] the created test run
    def start_run(session_id, suite_id, inputs)
      post('/api/test_runs', test_session_id: session_id, test_suite_id: suite_id, inputs:)
    end

    # @return [Hash] the test run, including +status+
    def test_run(run_id)
      get("/api/test_runs/#{run_id}")
    end

    # @return [Array<Hash>] every result recorded in the session
    def results(session_id)
      get("/api/test_sessions/#{session_id}/results")
    end

    # @return [Array<Hash>] session data (+name+/+value+ pairs), e.g. outputs of a waiting test
    def session_data(session_id)
      get("/api/test_sessions/#{session_id}/session_data")
    end

    # Polls a run until its status is one of +statuses+.
    #
    # @return [Hash] the test run
    # @raise [Error] if the run does not reach a target status within +timeout+ seconds
    def wait_for_run(run_id, statuses, timeout: 120)
      deadline = Time.now + timeout
      loop do
        run = test_run(run_id)
        return run if statuses.include?(run['status'])
        raise Error, "test run #{run_id} stuck in '#{run['status']}'" if Time.now > deadline

        sleep 1
      end
    end

    private

    def get(path)
      parse(@http.get(path), path)
    end

    def post(path, body)
      parse(@http.post(path, body.to_json, 'Content-Type' => 'application/json'), path)
    end

    def parse(response, path)
      raise Error, "#{path} returned HTTP #{response.status}" unless response.success?

      JSON.parse(response.body)
    end
  end
end
