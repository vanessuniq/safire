module Safire
  class Client
    attr_reader :config, :smart_metadata

    # Initialie Safire client with a set of config
    #
    # @param config an instance of Safire::Client::Config
    def initialize(config)
      @config = config
    end

    def smart_discovery
      @smart_metadata = SmartDiscovery.new(config.base_url).discover
    end
  end
end
