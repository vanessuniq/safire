module Safire
  module Protocols
    # Evaluates warning-only coverage of requested non-wildcard SMART FHIR scopes
    # against exhaustive UDAP +scopes_supported+ metadata.
    #
    # This collaborator deliberately does not authorize requests or decide hard
    # failures. Exact wildcard-advertisement policy remains with {Udap}; this
    # class only identifies non-wildcard scopes that cannot be locally proven to
    # be covered for diagnostic purposes.
    #
    # @api private
    class UdapScopeCoverage
      ACCESS_CONTEXTS = %w[patient user system].freeze
      INTERACTION_ORDER = %w[c r u d s].freeze
      V1_PERMISSIONS = {
        'read' => %w[r s].freeze,
        'write' => %w[c u d].freeze,
        '*' => INTERACTION_ORDER
      }.freeze
      FHIR_SCOPE_PATTERN = %r{\A(#{ACCESS_CONTEXTS.join('|')})/(\*|[A-Z][A-Za-z0-9]*)\.([^?]+)(?:\?(.+))?\z}
      ParsedScope = Data.define(:context, :resource, :permissions, :constraint)

      private_constant :ACCESS_CONTEXTS, :INTERACTION_ORDER, :V1_PERMISSIONS,
                       :FHIR_SCOPE_PATTERN, :ParsedScope

      def self.requested_wildcard?(scope)
        scope.is_a?(String) && scope.include?('*')
      end

      def initialize(advertised_scopes)
        unless advertised_scopes.is_a?(Array) && advertised_scopes.all?(String)
          raise ArgumentError, 'advertised_scopes must be an array of strings'
        end

        @advertised_scopes = immutable_strings(advertised_scopes)
        @parsed_advertised_scopes = @advertised_scopes.filter_map { |scope| parse_scope(scope) }.freeze
        freeze
      end

      def advertised_exactly?(scope)
        @advertised_scopes.include?(scope)
      end

      # Returns requested non-wildcard scopes not exactly advertised or covered
      # by recognized SMART FHIR resource scopes. Compatible advertised entries
      # may contribute a union of permissions for warning suppression only.
      #
      # @param requested_scopes [Array<String>]
      # @return [Array<String>] deduplicated uncovered scopes in request order
      def uncovered_non_wildcards_for_warning(requested_scopes)
        validate_requested_scopes!(requested_scopes)
        unique_scopes = requested_scopes.uniq
        if unique_scopes.any? { |scope| self.class.requested_wildcard?(scope) }
          raise ArgumentError, 'requested_scopes must not contain wildcard scopes'
        end

        unique_scopes.reject { |scope| advertised_exactly?(scope) || covered_fhir_scope?(scope) }
      end

      private

      def immutable_strings(values)
        values.map { |value| value.dup.freeze }.freeze
      end

      def validate_requested_scopes!(scopes)
        return if scopes.is_a?(Array) && scopes.all?(String)

        raise ArgumentError, 'requested_scopes must be an array of strings'
      end

      def covered_fhir_scope?(scope)
        requested = parse_scope(scope)
        return false unless requested

        advertised_permissions = @parsed_advertised_scopes.filter_map do |advertised|
          advertised.permissions if compatible_scope?(advertised, requested)
        end.flatten.uniq
        (requested.permissions - advertised_permissions).empty?
      end

      def compatible_scope?(advertised, requested)
        advertised.context == requested.context &&
          resource_covers?(advertised.resource, requested.resource) &&
          constraint_covers?(advertised.constraint, requested.constraint)
      end

      def resource_covers?(advertised, requested)
        advertised == '*' || advertised == requested
      end

      def constraint_covers?(advertised, requested)
        advertised.nil? || advertised == requested
      end

      def parse_scope(scope)
        match = FHIR_SCOPE_PATTERN.match(scope)
        return unless match

        permissions = normalize_permissions(match[3])
        return unless permissions

        ParsedScope.new(
          context: match[1],
          resource: match[2],
          permissions:,
          constraint: match[4]
        )
      end

      def normalize_permissions(value)
        return V1_PERMISSIONS.fetch(value) if V1_PERMISSIONS.key?(value)

        characters = value.chars
        return if characters.empty?
        return unless characters == INTERACTION_ORDER.select { |interaction| characters.include?(interaction) }

        characters.freeze
      end
    end
  end
end
