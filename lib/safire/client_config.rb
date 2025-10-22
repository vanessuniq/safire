# require_relative 'entity'

module Safire
  class ClientConfig < Entity
    # Attributes for Safire client configuration
    #
    # @!attribute [r] base_url
    #   @return [String] the base URL of the FHIR service
    ATTRIBUTES = %i[base_url].freeze

    attr_reader(*ATTRIBUTES)

    def initialize(config)
      super(config, ATTRIBUTES)
    end
  end
end
