module Safire
  class Entity
    def initialize(params, attributes)
      attributes.each { |name| instance_variable_set("@#{name}", params[name] || params[name.to_s]) }
    end

    def to_hash
      hash = {}
      instance_variables.each do |var|
        key = var.to_s.delete_prefix('@').to_sym
        value = instance_variable_get(var)
        hash[key] = sensitive_attributes.include?(key) && !value.nil? ? '[FILTERED]' : value
      end
      hash.deep_symbolize_keys
    end

    protected

    # Returns attribute names whose values are masked as '[FILTERED]' in #to_hash.
    #
    # @return [Array<Symbol>]
    def sensitive_attributes
      []
    end
  end
end
