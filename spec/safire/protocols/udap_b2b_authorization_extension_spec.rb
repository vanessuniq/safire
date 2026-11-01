require 'spec_helper'

RSpec.describe Safire::Protocols::UdapB2bAuthorizationExtension do
  subject(:extension) { described_class.new(input) }

  let(:organization_id) { 'https://fhir.example.com/Organization/123' }
  let(:purpose) { 'urn:oid:2.16.840.1.113883.5.8#TREAT' }
  let(:minimal_input) { { organization_id:, purpose_of_use: [purpose] } }
  let(:full_input) do
    {
      'version' => '1',
      'subject_name' => 'Dr. Jane Example',
      'subject_id' => 'urn:oid:2.16.840.1.113883.4.6#1234567890',
      'subject_role' => 'http://nucc.org/provider-taxonomy#207Q00000X',
      'organization_name' => 'Example Clinic',
      'organization_id' => organization_id,
      'purpose_of_use' => [purpose, 'urn:oid:2.16.840.1.113883.5.8#HPAYMT'],
      'consent_policy' => ['https://consent.example.com/policy/opt-in'],
      'consent_reference' => ['https://fhir.example.com/Consent/abc']
    }
  end
  let(:input) { minimal_input }

  def expect_validation_error(input, attribute, reason = nil)
    expect { described_class.new(input) }.to raise_error(Safire::Errors::ValidationError) { |error|
      expect(error.attribute).to eq(attribute)
      expect(error.reason).to eq(reason) if reason
    }
  end

  describe 'EXTENSION_KEY' do
    it 'is the STU2 extension key name' do
      expect(described_class::EXTENSION_KEY).to eq('hl7-b2b')
    end
  end

  describe 'valid input' do
    it 'injects version "1" first for a minimal object' do
      expect(extension.to_h).to eq(
        'version' => '1',
        'organization_id' => organization_id,
        'purpose_of_use' => [purpose]
      )
      expect(extension.to_h.keys.first).to eq('version')
    end

    it 'accepts a fully populated object and orders members canonically' do
      result = described_class.new(full_input.to_a.reverse.to_h).to_h

      expect(result).to eq(full_input)
      expect(result.keys).to eq(full_input.keys)
    end

    it 'normalizes symbol keys to string keys' do
      symbolized = full_input.transform_keys(&:to_sym)

      expect(described_class.new(symbolized).to_h).to eq(full_input)
    end

    it 'accepts an explicit version "1"' do
      expect(described_class.new(minimal_input.merge(version: '1')).to_h['version']).to eq('1')
    end

    it 'accepts a non-URL absolute URI organization_id' do
      result = described_class.new(minimal_input.merge(organization_id: 'urn:oid:2.16.840.1.113883.19.5')).to_h

      expect(result['organization_id']).to eq('urn:oid:2.16.840.1.113883.19.5')
    end

    it 'accepts non-URI purpose_of_use codes' do
      expect(described_class.new(minimal_input.merge(purpose_of_use: ['TREAT'])).to_h['purpose_of_use'])
        .to eq(['TREAT'])
    end

    it 'accepts subject_name without subject_id or subject_role' do
      result = described_class.new(minimal_input.merge(subject_name: 'Batch Service')).to_h

      expect(result).not_to have_key('subject_id')
      expect(result['subject_name']).to eq('Batch Service')
    end

    it 'accepts consent_policy without consent_reference' do
      result = described_class.new(minimal_input.merge(consent_policy: ['urn:example:policy'])).to_h

      expect(result['consent_policy']).to eq(['urn:example:policy'])
    end

    it 'accepts an http consent_reference URL' do
      input = minimal_input.merge(consent_policy: ['urn:example:policy'],
                                  consent_reference: ['http://fhir.example.com/DocumentReference/1'])

      expect(described_class.new(input).to_h['consent_reference']).to eq(['http://fhir.example.com/DocumentReference/1'])
    end

    it 'treats nil optional members and nil version as absent' do
      input = minimal_input.merge(version: nil, subject_name: nil, subject_id: nil, consent_policy: nil,
                                  consent_reference: nil)

      expect(described_class.new(input).to_h.keys).to eq(%w[version organization_id purpose_of_use])
    end
  end

  describe 'immutability' do
    it 'returns a deeply frozen hash' do
      result = described_class.new(full_input).to_h

      expect(result).to be_frozen
      expect(result.keys).to all(be_frozen)
      expect(result.values).to all(be_frozen)
      expect(result['purpose_of_use']).to all(be_frozen)
      expect(extension).to be_frozen
    end

    it 'does not share or mutate caller objects' do
      caller_input = full_input.transform_values { |value| value.is_a?(Array) ? value.map(&:dup) : value.dup }
      result = described_class.new(caller_input).to_h

      caller_input['purpose_of_use'] << 'urn:example#OTHER'
      caller_input['organization_name'] << ' Changed'

      expect(result['purpose_of_use']).to eq(full_input['purpose_of_use'])
      expect(result['organization_name']).to eq('Example Clinic')
      expect(caller_input['organization_name']).not_to be_frozen
    end
  end

  describe 'input shape' do
    it 'rejects non-Hash input' do
      expect_validation_error([], :'hl7-b2b', 'must be a Hash')
    end

    it 'rejects non-String, non-Symbol keys' do
      expect_validation_error(minimal_input.merge(1 => 'x'), :'hl7-b2b', 'keys must be strings or symbols')
    end

    it 'rejects a key supplied as both String and Symbol' do
      expect_validation_error(minimal_input.merge('organization_id' => organization_id), :organization_id,
                              'must not be specified more than once')
    end

    it 'rejects a String/Symbol duplicate even when one value is nil, in either order' do
      base = minimal_input.except(:organization_id)
      [
        base.merge('organization_id' => nil, organization_id: organization_id),
        base.merge(organization_id: organization_id, 'organization_id' => nil),
        base.merge('subject_name' => nil, subject_name: nil)
      ].each do |input|
        expect { described_class.new(input) }
          .to raise_error(Safire::Errors::ValidationError, /must not be specified more than once/)
      end
    end

    it 'rejects URIs with malformed percent escapes or illegal characters' do
      ['urn:example:bad%ZZ', 'https://example.com/%ZZ', 'urn:example:a"b', 'https://example.com/a%2'].each do |bad|
        expect { described_class.new(minimal_input.merge(organization_id: bad)) }
          .to raise_error(Safire::Errors::ValidationError) { |error| expect(error.attribute).to eq(:organization_id) }
        expect { described_class.new(minimal_input.merge(consent_policy: [bad])) }
          .to raise_error(Safire::Errors::ValidationError) { |error| expect(error.attribute).to eq(:consent_policy) }
        expect do
          described_class.new(minimal_input.merge(consent_policy: ['urn:example:policy'], consent_reference: [bad]))
        end.to raise_error(Safire::Errors::ValidationError) { |error| expect(error.attribute).to eq(:consent_reference) }
      end
    end

    it 'accepts well-formed percent-encoded URIs' do
      result = described_class.new(minimal_input.merge(organization_id: 'https://example.com/org%20one')).to_h

      expect(result['organization_id']).to eq('https://example.com/org%20one')
    end

    it 'rejects unknown keys without echoing the value' do
      expect { described_class.new(minimal_input.merge(secret_member: 'sensitive-value')) }
        .to raise_error(Safire::Errors::ValidationError) { |error|
          expect(error.attribute).to eq(:secret_member)
          expect(error.message).not_to include('sensitive-value')
        }
    end
  end

  describe 'version' do
    it 'rejects "2"' do
      expect_validation_error(minimal_input.merge(version: '2'), :version, 'must be omitted or the string "1"')
    end

    it 'rejects integer 1' do
      expect_validation_error(minimal_input.merge(version: 1), :version)
    end
  end

  describe 'organization_id' do
    it 'is required' do
      expect_validation_error({ purpose_of_use: [purpose] }, :organization_id, 'is required')
    end

    it 'treats nil as missing' do
      expect_validation_error(minimal_input.merge(organization_id: nil), :organization_id, 'is required')
    end

    ['', '   ', '/Organization/123', 'Organization/123', 'example.com', 'urn:', 'https://example.com/a b',
     ' https://example.com'].each do |value|
      it "rejects #{value.inspect} without echoing it" do
        expect { described_class.new(minimal_input.merge(organization_id: value)) }
          .to raise_error(Safire::Errors::ValidationError) { |error|
            expect(error.attribute).to eq(:organization_id)
            expect(error.reason).to eq('must be an absolute URI string')
          }
      end
    end

    it 'rejects non-String values' do
      expect_validation_error(minimal_input.merge(organization_id: 123), :organization_id)
    end
  end

  describe 'purpose_of_use' do
    it 'is required' do
      expect_validation_error({ organization_id: }, :purpose_of_use, 'is required')
    end

    purpose = 'urn:oid:2.16.840.1.113883.5.8#TREAT'
    [[], [''], ['  '], [purpose, nil], [purpose, 1], purpose].each do |value|
      it "rejects #{value.inspect}" do
        expect_validation_error(minimal_input.merge(purpose_of_use: value), :purpose_of_use,
                                'must be a non-empty array of non-blank strings')
      end
    end
  end

  describe 'optional string members' do
    %i[organization_name subject_name].each do |field|
      ['', " \t", 42, ['name']].each do |value|
        it "rejects #{field} #{value.inspect}" do
          expect_validation_error(minimal_input.merge(field => value), field, 'must be a non-blank string')
        end
      end
    end

    %i[subject_id subject_role].each do |field|
      it "rejects a blank #{field}" do
        expect_validation_error(minimal_input.merge(subject_name: 'Dr. Jane Example', field => ' '), field,
                                'must be a non-blank string')
      end

      it "rejects #{field} without subject_name" do
        expect_validation_error(minimal_input.merge(field => 'value'), field, 'requires subject_name')
      end
    end
  end

  describe 'consent_policy' do
    [[], [''], ['relative/policy'], ['https://example.com/p', 5], 'urn:example:policy'].each do |value|
      it "rejects #{value.inspect}" do
        expect_validation_error(minimal_input.merge(consent_policy: value), :consent_policy,
                                'must be a non-empty array of absolute URI strings')
      end
    end
  end

  describe 'consent_reference' do
    let(:with_policy) { minimal_input.merge(consent_policy: ['urn:example:policy']) }

    it 'rejects consent_reference without consent_policy' do
      expect_validation_error(minimal_input.merge(consent_reference: ['https://fhir.example.com/Consent/1']),
                              :consent_reference, 'requires consent_policy')
    end

    [[], [''], ['Consent/1'], ['urn:uuid:3e4f'], ['ftp://example.com/Consent/1'], ['https:///Consent/1'],
     ['https://fhir.example.com/Consent/1', nil]].each do |value|
      it "rejects #{value.inspect}" do
        expect_validation_error(with_policy.merge(consent_reference: value), :consent_reference,
                                'must be a non-empty array of absolute HTTP(S) URL strings')
      end
    end
  end
end
