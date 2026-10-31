module Safire
  module Protocols
    # Applies Safire's client-side UDAP scope-negotiation checks to a set of
    # requested scopes before a request is sent.
    #
    # {https://hl7.org/fhir/us/udap-security/STU2/general.html#scope-negotiation
    # UDAP Security STU2 General Requirements: Scope negotiation} states that its
    # constraints "apply for both registration requests and access token
    # requests" and that "A client application **MAY** request a wildcard scope
    # only if wildcards are specified in the server's +scopes_supported+
    # metadata list." Safire applies a stricter local check: a requested scope
    # token containing a literal +*+ is a wildcard and must appear exactly in
    # +scopes_supported+.
    #
    # The +operation+ selects the lifecycle policy (see ADR-015):
    #
    # - +:register+ (registration and modification) and +:token+ (access token
    #   requests) raise {Errors::ValidationError} (attribute +:scope+) for an
    #   unadvertised requested wildcard, and {Errors::DiscoveryError} when
    #   +scopes_supported+ provides no usable scope strings while a wildcard
    #   must be evaluated. Their messages do not name the operation.
    # - +:cancel+ (registration cancellation) reports both conditions as
    #   value-free warnings so existing access can be removed.
    #
    # Non-wildcard scopes are never rejected locally under any operation:
    # unlisted or unconfirmed tokens produce one aggregated value-free warning
    # and the server remains authoritative. Messages report only scope category
    # and deduplicated count, never scope values.
    #
    # @example
    #   UdapScopeNegotiation.new(
    #     scopes_supported: metadata.scopes_supported,
    #     operation: :token,
    #     discovery_endpoint: 'https://fhir.example.com/.well-known/udap'
    #   ).evaluate!(%w[system/Patient.rs system/*.rs])
    #
    # @api private
    class UdapScopeNegotiation
      OPERATIONS = %i[register cancel token].freeze
      DISCOVERY_LABEL = 'UDAP metadata'.freeze
      CANCELLATION_LIFECYCLE =
        'cancellation proceeds and remains warning-only so existing access can be removed'.freeze
      UNUSABLE_ADVERTISEMENT =
        'scopes_supported must be an array containing at least one usable scope string ' \
        'to evaluate requested wildcard scopes'.freeze
      UNADVERTISED_WILDCARD_RULE =
        'not advertised exactly in scopes_supported ' \
        '(UDAP Security STU2 permits requesting a wildcard scope only when it is advertised)'.freeze

      private_constant :OPERATIONS, :DISCOVERY_LABEL, :CANCELLATION_LIFECYCLE,
                       :UNUSABLE_ADVERTISEMENT, :UNADVERTISED_WILDCARD_RULE

      # @param scopes_supported [Object] the discovered +scopes_supported+ value,
      #   as published (may be +nil+, a non-array, or contain malformed entries)
      # @param operation [Symbol] +:register+, +:cancel+, or +:token+
      # @param discovery_endpoint [String] the UDAP well-known URL (including any
      #   +community+ query) reported as {Errors::DiscoveryError#endpoint}
      # @raise [ArgumentError] when +operation+ is not supported
      def initialize(scopes_supported:, operation:, discovery_endpoint:)
        raise ArgumentError, "unsupported scope negotiation operation: #{operation.inspect}" unless
          OPERATIONS.include?(operation)

        @advertised = usable_advertised_scopes(scopes_supported)
        @operation = operation
        @discovery_endpoint = discovery_endpoint
        freeze
      end

      # Evaluates requested scopes, raising or warning per the operation policy.
      #
      # @param requested_scopes [Array<String>] individual non-blank scope
      #   tokens, already split and normalized by the caller; duplicates are
      #   ignored
      # @return [void]
      # @raise [Errors::ValidationError] (+:register+, +:token+) when a requested
      #   wildcard is not advertised exactly
      # @raise [Errors::DiscoveryError] (+:register+, +:token+) when a wildcard
      #   is requested and +scopes_supported+ provides no usable scope strings
      # @raise [ArgumentError] when +requested_scopes+ is not an array of
      #   non-blank strings
      def evaluate!(requested_scopes)
        wildcards, non_wildcards = scope_groups(requested_scopes)
        return handle_unusable_advertisement(wildcards, non_wildcards) if @advertised.blank?

        coverage = UdapScopeCoverage.new(@advertised)
        handle_unadvertised_wildcards(wildcards.reject { |scope| coverage.advertised_exactly?(scope) })
        warn_uncovered_non_wildcards(coverage.uncovered_non_wildcards_for_warning(non_wildcards))
      end

      private

      def scope_groups(requested_scopes)
        unless requested_scopes.is_a?(Array) && requested_scopes.all? { |s| s.is_a?(String) && s.present? }
          raise ArgumentError, 'requested_scopes must be an array of non-blank strings'
        end

        requested_scopes.uniq.partition { |scope| UdapScopeCoverage.requested_wildcard?(scope) }
      end

      # A malformed sibling entry is a server-conformance defect for
      # `UdapMetadata#valid?` to diagnose; it does not prevent Safire from
      # deciding against the usable entries.
      def usable_advertised_scopes(scopes)
        return unless scopes.is_a?(Array)

        scopes.select { |scope| scope.is_a?(String) && scope.present? }.freeze
      end

      def enforcing?
        @operation != :cancel
      end

      # When +scopes_supported+ is unusable, a requested wildcard cannot be
      # shown to be advertised, so enforcing operations raise. Cancellation
      # removes access, so scope-advertisement drift stays warning-only there
      # (see ADR-015).
      def handle_unusable_advertisement(wildcards, non_wildcards)
        if wildcards.any? && enforcing?
          raise Errors::DiscoveryError.new(
            endpoint: @discovery_endpoint,
            error_description: UNUSABLE_ADVERTISEMENT,
            label: DISCOVERY_LABEL
          )
        end

        warn_cancellation_unconfirmed_wildcards(wildcards)
        warn_unconfirmed_non_wildcards(non_wildcards)
      end

      def handle_unadvertised_wildcards(scopes)
        return if scopes.empty?
        return warn_cancellation_unadvertised_wildcards(scopes) unless enforcing?

        raise Errors::ValidationError.new(
          attribute: :scope,
          reason: "#{scope_summary(scopes, 'wildcard')} #{UNADVERTISED_WILDCARD_RULE}"
        )
      end

      def warn_cancellation_unadvertised_wildcards(scopes)
        emit_scope_diagnostic(
          scopes,
          category: 'wildcard',
          detail: 'no exact advertisement in scopes_supported',
          lifecycle: CANCELLATION_LIFECYCLE
        )
      end

      def warn_cancellation_unconfirmed_wildcards(scopes)
        emit_scope_diagnostic(
          scopes,
          category: 'wildcard',
          detail: 'exact advertisement cannot be confirmed because scopes_supported provides no usable scope strings',
          lifecycle: CANCELLATION_LIFECYCLE
        )
      end

      def warn_uncovered_non_wildcards(scopes)
        emit_scope_diagnostic(
          scopes,
          category: 'non-wildcard',
          detail: 'coverage is not listed or locally proven by scopes_supported; ' \
                  'proceeding with server-side scope negotiation'
        )
      end

      def warn_unconfirmed_non_wildcards(scopes)
        emit_scope_diagnostic(
          scopes,
          category: 'non-wildcard',
          detail: 'coverage cannot be confirmed because scopes_supported provides no usable scope strings; ' \
                  'proceeding with server-side scope negotiation'
        )
      end

      # Value-free by design: reports category and deduplicated count, never raw
      # requested scope values, which can carry sensitive search constraints.
      def emit_scope_diagnostic(scopes, category:, detail:, lifecycle: nil)
        return if scopes.empty?

        message = "[UDAP] #{scope_summary(scopes, category)}; #{detail}"
        message = "#{message}; #{lifecycle}" if lifecycle
        Safire.logger.warn(message)
      end

      def scope_summary(scopes, category)
        "requested #{category} scope count=#{scopes.length}"
      end
    end
  end
end
