require 'logger'
require 'stringio'

module SafireCompliance
  # Records local (non-Inferno) checks of Safire behavior, capturing Safire's log output per check.
  #
  # A check passes when its block returns truthy; a Safire error or +ArgumentError+ makes it
  # +error+. Detail text is passed through the run's {Redactor} before it is stored.
  class LocalChecks
    attr_reader :entries

    def initialize(redactor)
      @redactor = redactor
      @entries = []
      @log = StringIO.new
    end

    # Routes Safire logging into this recorder (WARN and above, no HTTP logging).
    def configure_safire_logging
      Safire.configure do |c|
        c.logger = Logger.new(@log)
        c.log_level = Logger::WARN
        c.log_http = false
      end
    end

    # @yieldreturn [Boolean] whether the check passed
    def check(id, title)
      @log.truncate(0)
      @log.rewind
      passed = yield
      record(id, title, passed ? 'pass' : 'fail', @log.string)
    rescue Safire::Errors::Error, ArgumentError => e
      record(id, title, 'error', "#{e.class}: #{e.message}")
    end

    # Passes when the block raises +error_class+ (an expected rejection in a negative control).
    def expect_error(id, title, error_class)
      yield
      record(id, title, 'fail', 'no error raised')
    rescue error_class => e
      record(id, title, 'pass', "#{e.class}: #{e.message}")
    rescue Safire::Errors::Error, ArgumentError => e
      record(id, title, 'fail', "unexpected #{e.class}: #{e.message}")
    end

    def record(id, title, result, detail)
      @entries << { id:, title:, result:, detail: @redactor.call(detail.to_s.strip) }
    end
  end
end
