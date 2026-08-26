require 'spec_helper'

RSpec.describe Safire::Protocols::UdapScopeCoverage do
  subject(:coverage) { described_class.new(advertised_scopes) }

  let(:advertised_scopes) { ['system/*.rs'] }

  describe '.requested_wildcard?' do
    it 'classifies any literal asterisk as a requested wildcard' do
      expect(described_class.requested_wildcard?('system/Patient.*')).to be(true)
      expect(described_class.requested_wildcard?('system/*.rs')).to be(true)
      expect(described_class.requested_wildcard?('custom:*:read')).to be(true)
    end

    it 'does not classify lookalike text as a wildcard' do
      expect(described_class.requested_wildcard?('urn:example:wildcard')).to be(false)
    end
  end

  describe '#advertised_exactly?' do
    it 'uses exact, case-sensitive membership' do
      expect(coverage.advertised_exactly?('system/*.rs')).to be(true)
      expect(coverage.advertised_exactly?('system/*.RS')).to be(false)
    end
  end

  describe '#uncovered_non_wildcards_for_warning' do
    it 'accepts exact custom-scope matches without interpreting their syntax' do
      coverage = described_class.new(['urn:example:read'])

      expect(coverage.uncovered_non_wildcards_for_warning(['urn:example:read'])).to eq([])
    end

    it 'returns custom scopes that are not advertised exactly' do
      expect(coverage.uncovered_non_wildcards_for_warning(['urn:example:read']))
        .to eq(['urn:example:read'])
    end

    it 'covers specific resources and narrower permissions with an advertised resource wildcard' do
      requested = %w[system/Patient.rs system/Observation.rs system/Condition.r]

      expect(coverage.uncovered_non_wildcards_for_warning(requested)).to eq([])
    end

    it 'does not depend on a hard-coded FHIR resource catalog' do
      expect(coverage.uncovered_non_wildcards_for_warning(['system/CommunityDefinedResource.r'])).to eq([])
    end

    it 'rejects a mismatched access context' do
      expect(coverage.uncovered_non_wildcards_for_warning(['patient/Patient.r']))
        .to eq(['patient/Patient.r'])
    end

    it 'rejects a mismatched resource when no resource wildcard is advertised' do
      coverage = described_class.new(['system/Observation.rs'])

      expect(coverage.uncovered_non_wildcards_for_warning(['system/Patient.r']))
        .to eq(['system/Patient.r'])
    end

    it 'rejects permissions broader than the advertised set' do
      expect(coverage.uncovered_non_wildcards_for_warning(['system/Patient.cruds']))
        .to eq(['system/Patient.cruds'])
    end

    it 'allows an unconstrained advertisement to cover a constrained request' do
      requested = 'system/Observation.rs?category=laboratory'

      expect(coverage.uncovered_non_wildcards_for_warning([requested])).to eq([])
    end

    it 'allows an identical advertised search constraint' do
      requested = 'system/Observation.rs?category=laboratory'
      coverage = described_class.new([requested])

      expect(coverage.uncovered_non_wildcards_for_warning([requested])).to eq([])
    end

    it 'does not let a constrained advertisement cover an unconstrained request' do
      coverage = described_class.new(['system/Observation.rs?category=laboratory'])

      expect(coverage.uncovered_non_wildcards_for_warning(['system/Observation.rs']))
        .to eq(['system/Observation.rs'])
    end

    it 'does not infer relationships between different search constraints' do
      coverage = described_class.new(['system/Observation.rs?category=laboratory'])
      requested = 'system/Observation.rs?category=vital-signs'

      expect(coverage.uncovered_non_wildcards_for_warning([requested])).to eq([requested])
    end

    it 'normalizes advertised SMART v1 read permissions' do
      coverage = described_class.new(['system/Patient.read'])

      expect(coverage.uncovered_non_wildcards_for_warning(['system/Patient.rs'])).to eq([])
    end

    it 'normalizes advertised SMART v1 write permissions' do
      coverage = described_class.new(['system/Patient.write'])

      expect(coverage.uncovered_non_wildcards_for_warning(['system/Patient.cud'])).to eq([])
    end

    it 'normalizes advertised SMART v1 wildcard permissions for a non-wildcard request' do
      coverage = described_class.new(['system/Patient.*'])

      expect(coverage.uncovered_non_wildcards_for_warning(['system/Patient.rs'])).to eq([])
    end

    it 'normalizes a requested SMART v1 read permission when it has no literal wildcard' do
      coverage = described_class.new(['system/Patient.rs'])

      expect(coverage.uncovered_non_wildcards_for_warning(['system/Patient.read'])).to eq([])
    end

    it 'treats out-of-order interaction suffixes as unrecognized syntax' do
      expect(coverage.uncovered_non_wildcards_for_warning(['system/Patient.sr']))
        .to eq(['system/Patient.sr'])
    end

    it 'still accepts an exact match for unrecognized interaction syntax' do
      coverage = described_class.new(['system/Patient.sr'])

      expect(coverage.uncovered_non_wildcards_for_warning(['system/Patient.sr'])).to eq([])
    end

    it 'uses compatible advertised fragments as a warning-only permission union' do
      coverage = described_class.new(%w[system/Patient.r system/Patient.s])

      expect(coverage.uncovered_non_wildcards_for_warning(['system/Patient.rs'])).to eq([])
    end

    it 'does not let an unrelated advertised wildcard suppress a warning' do
      coverage = described_class.new(['user/*.rs'])

      expect(coverage.uncovered_non_wildcards_for_warning(['system/Patient.r']))
        .to eq(['system/Patient.r'])
    end

    it 'deduplicates requested scopes while preserving their original order' do
      requested = %w[custom:b custom:a custom:b custom:c custom:a]

      expect(coverage.uncovered_non_wildcards_for_warning(requested))
        .to eq(%w[custom:b custom:a custom:c])
    end

    it 'rejects requested wildcards so callers must evaluate exact advertisement separately' do
      expect { coverage.uncovered_non_wildcards_for_warning(['system/Patient.*']) }
        .to raise_error(ArgumentError, /must not contain wildcard scopes/)
    end

    [nil, 'system/Patient.rs', ['system/Patient.rs', nil]].each do |value|
      it "rejects malformed requested scopes #{value.inspect}" do
        expect { coverage.uncovered_non_wildcards_for_warning(value) }
          .to raise_error(ArgumentError, /requested_scopes must be an array of strings/)
      end
    end

    it 'does not mutate caller-owned arrays or strings' do
      advertised = ['system/*.rs']
      requested = ['system/Patient.rs']

      described_class.new(advertised).uncovered_non_wildcards_for_warning(requested)

      expect(advertised).to eq(['system/*.rs'])
      expect(requested).to eq(['system/Patient.rs'])
      expect(advertised.first).not_to be_frozen
      expect(requested.first).not_to be_frozen
    end
  end

  describe 'constructor validation' do
    [nil, 'system/*.rs', ['system/*.rs', nil]].each do |value|
      it "rejects #{value.inspect}" do
        expect { described_class.new(value) }
          .to raise_error(ArgumentError, /advertised_scopes must be an array of strings/)
      end
    end
  end
end
