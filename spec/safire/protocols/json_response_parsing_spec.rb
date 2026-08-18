require 'spec_helper'

RSpec.describe Safire::Protocols::JSONResponseParsing do
  describe '.parse_object' do
    it 'returns a deeply normalized copy of a Hash without mutating the caller' do
      client_id = +'client-123'
      body = {
        client_id:,
        metadata: [{ redirect_uri: 'https://app.example.com/callback' }]
      }

      result = described_class.parse_object(body)

      expect(result).to eq(
        'client_id' => 'client-123',
        'metadata' => [{ 'redirect_uri' => 'https://app.example.com/callback' }]
      )
      expect(body).to eq(
        client_id: 'client-123',
        metadata: [{ redirect_uri: 'https://app.example.com/callback' }]
      )
      expect(result).not_to equal(body)
      expect(result['client_id']).not_to equal(client_id)
    end

    it 'parses a raw JSON object string' do
      body = '{"client_id":"client-123","metadata":{"active":true}}'

      expect(described_class.parse_object(body)).to eq(
        'client_id' => 'client-123',
        'metadata' => { 'active' => true }
      )
    end

    it 'allows a shared non-recursive object to appear more than once' do
      shared = { value: 1 }

      expect(described_class.parse_object(left: shared, right: shared)).to eq(
        'left' => { 'value' => 1 },
        'right' => { 'value' => 1 }
      )
    end

    it 'rejects string and symbol keys that normalize to the same key' do
      expect(described_class.parse_object('client_id' => 'first', client_id: 'second')).to be_nil
    end

    it 'rejects nested normalization collisions' do
      body = { metadata: { 'active' => true, active: false } }

      expect(described_class.parse_object(body)).to be_nil
    end

    it 'rejects unsupported Hash key types' do
      expect(described_class.parse_object(Object.new => 'value')).to be_nil
    end

    it 'rejects unsupported value types' do
      expect(described_class.parse_object('generated_at' => Time.now)).to be_nil
    end

    it 'rejects non-finite JSON numbers' do
      expect(described_class.parse_object('value' => Float::NAN)).to be_nil
      expect(described_class.parse_object('value' => Float::INFINITY)).to be_nil
      expect(described_class.parse_object('value' => -Float::INFINITY)).to be_nil
    end

    it 'rejects a recursive Hash' do
      body = {}
      body['self'] = body

      expect(described_class.parse_object(body)).to be_nil
    end

    it 'rejects a recursive Array' do
      values = []
      values << values

      expect(described_class.parse_object('values' => values)).to be_nil
    end

    it 'rejects an excessively nested adapter-supplied structure' do
      body = { 'value' => true }
      150.times { body = { 'nested' => body } }

      expect(described_class.parse_object(body)).to be_nil
    end

    it 'rejects invalid string encoding' do
      body = { 'value' => "\xFF".force_encoding(Encoding::UTF_8) }

      expect(described_class.parse_object(body)).to be_nil
    end

    it 'rejects binary strings that cannot be represented as JSON text' do
      expect(described_class.parse_object('value' => "\xFF".b)).to be_nil
    end

    it 'transcodes compatible strings to UTF-8 without mutating the caller' do
      value = "caf\xE9".force_encoding(Encoding::ISO_8859_1)

      result = described_class.parse_object('value' => value)

      expect(result['value']).to eq("caf\u00E9")
      expect(result['value'].encoding).to eq(Encoding::UTF_8)
      expect(value.encoding).to eq(Encoding::ISO_8859_1)
    end

    [
      nil,
      '',
      '{not-json',
      '[]',
      '"value"',
      '123',
      'true',
      'null',
      [],
      'value',
      123,
      true
    ].each do |body|
      it "rejects non-object input #{body.inspect}" do
        expect(described_class.parse_object(body)).to be_nil
      end
    end
  end
end
