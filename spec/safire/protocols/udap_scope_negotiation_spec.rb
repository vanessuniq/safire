require 'spec_helper'

RSpec.describe Safire::Protocols::UdapScopeNegotiation do
  subject(:negotiation) do
    described_class.new(scopes_supported:, operation:, discovery_endpoint: endpoint)
  end

  let(:endpoint) { 'https://fhir.example.com/.well-known/udap?community=urn%3Aexample%3Acommunity' }
  let(:scopes_supported) { ['system/*.rs'] }
  let(:operation) { :register }
  let(:sensitive_scope) { 'patient/Observation.rs?code=mrn-123' }
  let(:messages) { [] }

  before do
    allow(Safire.logger).to receive(:warn) { |message| messages << message }
  end

  shared_examples 'warning-only wildcard negotiation' do
    it 'warns without raising for deduplicated unadvertised wildcards' do
      described_class.new(scopes_supported: ['system/Patient.rs'], operation:, discovery_endpoint: endpoint)
                     .evaluate!(['system/*.rs', 'patient/*.rs', 'system/*.rs'])

      expect(messages).to contain_exactly(
        "[UDAP] requested wildcard scope count=2; no exact advertisement in scopes_supported; #{lifecycle}"
      )
    end

    [nil, [], 'system/*.rs', [nil, '']].each do |advertised|
      it "warns without raising when scopes_supported is #{advertised.inspect}" do
        described_class.new(scopes_supported: advertised, operation:, discovery_endpoint: endpoint)
                       .evaluate!(['system/*.rs', 'system/Patient.rs'])

        expect(messages).to eq(
          [
            '[UDAP] requested wildcard scope count=1; exact advertisement cannot be confirmed because ' \
            "scopes_supported provides no usable scope strings; #{lifecycle}",
            '[UDAP] requested non-wildcard scope count=1; coverage cannot be confirmed because ' \
            'scopes_supported provides no usable scope strings; proceeding with server-side scope negotiation'
          ]
        )
      end
    end
  end

  def capture_error
    negotiation.evaluate!(requested)
    nil
  rescue Safire::Errors::Error => e
    e
  end

  describe '.new' do
    it 'rejects an unsupported operation' do
      expect { described_class.new(scopes_supported:, operation: :modify, discovery_endpoint: endpoint) }
        .to raise_error(ArgumentError, /unsupported scope negotiation operation/)
    end
  end

  describe '#evaluate!' do
    it 'rejects requested scopes that are not an array of non-blank strings' do
      ['system/*.rs', [nil], [''], [' ']].each do |requested|
        expect { negotiation.evaluate!(requested) }
          .to raise_error(ArgumentError, /array of non-blank strings/)
      end
    end

    it 'accepts an empty request without warnings' do
      expect { negotiation.evaluate!([]) }.not_to raise_error
      expect(messages).to be_empty
    end

    %i[register token cancel authorize].each do |op|
      context "with operation #{op.inspect}" do
        let(:operation) { op }

        it 'accepts a wildcard advertised exactly without warnings' do
          expect { negotiation.evaluate!(['system/*.rs']) }.not_to raise_error
          expect(messages).to be_empty
        end

        it 'does not warn when advertised FHIR scope coverage proves a non-wildcard request' do
          negotiation.evaluate!(%w[system/Patient.rs system/Observation.r])

          expect(messages).to be_empty
        end

        it 'emits one value-free warning for deduplicated uncovered non-wildcard scopes' do
          negotiation.evaluate!([sensitive_scope, 'custom:tenant-a', 'system/Patient.cud', 'custom:tenant-a'])

          expect(messages).to contain_exactly(
            '[UDAP] requested non-wildcard scope count=3; coverage is not listed or locally proven by ' \
            'scopes_supported; proceeding with server-side scope negotiation'
          )
        end

        it 'ignores malformed sibling entries when deciding against usable advertisements' do
          described_class.new(
            scopes_supported: ['system/*.rs', nil, '', 42, { 'scope' => 'x' }],
            operation:, discovery_endpoint: endpoint
          ).evaluate!(%w[system/*.rs system/Patient.r])

          expect(messages).to be_empty
        end

        [nil, [], 'system/*.rs', [nil, '', '  ']].each do |advertised|
          it "warns once for non-wildcard scopes when scopes_supported is #{advertised.inspect}" do
            described_class.new(scopes_supported: advertised, operation:, discovery_endpoint: endpoint)
                           .evaluate!(['system/Patient.rs', 'system/Patient.rs', sensitive_scope])

            expect(messages).to contain_exactly(
              '[UDAP] requested non-wildcard scope count=2; coverage cannot be confirmed because ' \
              'scopes_supported provides no usable scope strings; proceeding with server-side scope negotiation'
            )
          end
        end
      end
    end

    %i[register token].each do |op|
      context "with enforcing operation #{op.inspect}" do
        let(:operation) { op }
        let(:scopes_supported) { ['system/Patient.rs', 'system/Observation.*', nil] }
        let(:requested) { ['system/*.rs', 'patient/*.rs', 'system/*.rs', 'custom:tenant-a'] }

        it 'raises a value-free ValidationError for deduplicated unadvertised wildcards' do
          error = capture_error

          expect(error).to be_a(Safire::Errors::ValidationError)
          expect(error.attribute).to eq(:scope)
          expect(error.reason).to eq(
            'requested wildcard scope count=2 not advertised exactly in scopes_supported ' \
            '(UDAP Security STU2 permits requesting a wildcard scope only when it is advertised)'
          )
          expect(error.message).not_to include('*.rs')
          expect(error.message).not_to match(/registration/i)
        end

        it 'requires exact wildcard advertisement rather than broader coverage' do
          negotiation = described_class.new(
            scopes_supported: ['system/*.cruds'], operation:, discovery_endpoint: endpoint
          )

          expect { negotiation.evaluate!(['system/Patient.*']) }
            .to raise_error(Safire::Errors::ValidationError, /wildcard scope count=1 not advertised exactly/)
        end

        it 'checks wildcards before warning about non-wildcard coverage' do
          capture_error

          expect(messages).to be_empty
        end

        [nil, [], 'system/*.rs', [nil, ''], { 'scope' => 'system/*.rs' }].each do |advertised|
          it "raises DiscoveryError for a requested wildcard when scopes_supported is #{advertised.inspect}" do
            negotiation = described_class.new(scopes_supported: advertised, operation:, discovery_endpoint: endpoint)

            expect { negotiation.evaluate!(['system/*.rs', sensitive_scope]) }.to raise_error(
              Safire::Errors::DiscoveryError
            ) do |error|
              expect(error.endpoint).to eq(endpoint)
              expect(error.label).to eq('UDAP metadata')
              expect(error.status).to be_nil
              expect(error.error_description).to eq(
                'scopes_supported must be an array containing at least one usable scope string ' \
                'to evaluate requested wildcard scopes'
              )
              expect(error.message).not_to include('*.rs', 'mrn-123')
              expect(error.message).not_to match(/registration/i)
            end
            expect(messages).to be_empty
          end
        end
      end
    end

    context 'with operation :cancel' do
      let(:operation) { :cancel }
      let(:lifecycle) { 'cancellation proceeds and remains warning-only so existing access can be removed' }

      it_behaves_like 'warning-only wildcard negotiation'
    end

    context 'with operation :authorize' do
      let(:operation) { :authorize }
      let(:lifecycle) do
        'the authorization request proceeds because UDAP Security STU2 scope negotiation ' \
          'names registration and token requests only; the authorization server decides'
      end

      it_behaves_like 'warning-only wildcard negotiation'

      it 'does not raise when a wildcard is requested and the advertisement is unusable' do
        expect do
          described_class.new(scopes_supported: { 'scope' => 'patient/*.rs' }, operation:, discovery_endpoint: endpoint)
                         .evaluate!(['patient/*.rs'])
        end.not_to raise_error
      end
    end

    it 'never includes requested scope values in any warning' do
      %i[register token cancel authorize].each do |op|
        described_class.new(scopes_supported: ['system/Patient.r'], operation: op, discovery_endpoint: endpoint)
                       .evaluate!([sensitive_scope, 'custom:tenant-a'])
      end
      described_class.new(scopes_supported: nil, operation: :cancel, discovery_endpoint: endpoint)
                     .evaluate!(['system/*.rs?patient=mrn-123', sensitive_scope])

      expect(messages).not_to be_empty
      expect(messages.join("\n")).not_to include('mrn-123', 'tenant-a', 'Observation', 'Patient')
    end
  end
end
