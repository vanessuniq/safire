module SafireCompliance
  # Removes secret values (client secrets, codes, verifiers, tokens) from report text.
  #
  # Inferno's result messages can quote request values, e.g. a PKCE challenge or an unknown
  # code. Every secret the harness handles is registered here and replaced before reporting.
  class Redactor
    PLACEHOLDER = '[redacted]'.freeze

    def initialize
      @secrets = []
    end

    # @param values [Array<String, nil>] secret values to scrub from report text
    def add(*values)
      values.flatten.each { |v| @secrets << v.to_s if v.to_s.length >= 6 }
    end

    # @return [String] +text+ with every registered secret replaced
    def call(text)
      return text unless text.is_a?(String)

      @secrets.uniq.sort_by { |s| -s.length }.reduce(text) { |acc, s| acc.gsub(s, PLACEHOLDER) }
    end
  end
end
