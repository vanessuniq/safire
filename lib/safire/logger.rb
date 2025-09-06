require 'logger'
require 'json'
require 'time'

module Safire
  # Custom logger for Safire
  class Logger
    LEVELS = {
      debug: Logger::DEBUG,
      info: Logger::INFO,
      warn: Logger::WARN,
      error: Logger::ERROR,
      fatal: Logger::FATAL
    }.freeze

    def initialize(output = $stdout, level: :info, format: :text)
      @logger = Logger.new(output)
      @logger.level = LEVELS[level] || Logger::INFO
      @format = format.to_sym
      setup_formatter
    end

    %i[debug info warn error fatal].each do |level|
      define_method(level) { |message = nil, **metadata, &block| log(level, message, metadata, &block) }
    end

    private

    def log(level, message, metadata, &block)
      # Ruby stdlib Logger doesn’t have predicate methods like logger.info?
      # We’ll rely on level filtering internally.
      payload = {
        timestamp: Time.now.utc.iso8601,
        level: level.to_s.upcase,
        message: message || block&.call,
        component: 'safire'
      }.merge(metadata)

      @logger.add(LEVELS[level]) { format_message(payload) }
    end

    def setup_formatter
      @logger.formatter =
        if @format == :json
          proc { |_severity, _datetime, _progname, msg| "#{msg}\n" }
        else
          proc { |severity, datetime, progname, msg| "[#{datetime.utc.iso8601}] #{severity} #{progname}: #{msg}\n" }
        end
    end

    def format_message(data)
      return JSON.generate(data) if @format == :json

      meta = data.dup.tap { |h| %i[timestamp level message component].each { |k| h.delete(k) } }
      meta.empty? ? data[:message].to_s : "#{data[:message]} #{meta.inspect}"
    end
  end
end
