require 'spec_helper'

RSpec.describe Safire::PKCE do
  describe '.generate_code_verifier' do
    it 'generates a code verifier' do
      verifier = described_class.generate_code_verifier
      expect(verifier).to be_a(String)
      expect(verifier).not_to be_empty
    end

    it 'generates a URL-safe base64 string' do
      verifier = described_class.generate_code_verifier
      expect(verifier).to match(/\A[A-Za-z0-9_-]+\z/)
    end

    it 'generates a verifier of 128 characters' do
      verifier = described_class.generate_code_verifier
      expect(verifier.length).to eq(128)
    end

    it 'does not include padding characters' do
      verifier = described_class.generate_code_verifier
      expect(verifier).not_to include('=')
    end

    it 'generates unique verifiers on each call' do
      verifier1 = described_class.generate_code_verifier
      verifier2 = described_class.generate_code_verifier
      expect(verifier1).not_to eq(verifier2)
    end

    it 'generates verifiers within RFC 7636 length requirements' do
      verifier = described_class.generate_code_verifier
      # RFC 7636 requires 43-128 characters
      expect(verifier.length).to be >= 43
      expect(verifier.length).to be <= 128
    end
  end

  describe '.generate_code_challenge' do
    let(:code_verifier) { described_class.generate_code_verifier }

    it 'generates a code challenge from valid verifier' do
      challenge = described_class.generate_code_challenge(code_verifier)
      expect(challenge).to be_a(String)
      expect(challenge).not_to be_empty
    end

    it 'generates a URL-safe base64 string' do
      challenge = described_class.generate_code_challenge(code_verifier)
      expect(challenge).to match(/\A[A-Za-z0-9_-]+\z/)
    end

    it 'does not include padding characters' do
      challenge = described_class.generate_code_challenge(code_verifier)
      expect(challenge).not_to include('=')
    end

    it 'generates the same challenge for the same verifier' do
      challenge1 = described_class.generate_code_challenge(code_verifier)
      challenge2 = described_class.generate_code_challenge(code_verifier)
      expect(challenge1).to eq(challenge2)
    end

    it 'generates different challenges for different verifiers' do
      verifier2 = described_class.generate_code_verifier
      challenge1 = described_class.generate_code_challenge(code_verifier)
      challenge2 = described_class.generate_code_challenge(verifier2)
      expect(challenge1).not_to eq(challenge2)
    end

    it 'generates a 43-character challenge (SHA256 base64url encoded)' do
      challenge = described_class.generate_code_challenge(code_verifier)
      # SHA256 produces 32 bytes, base64url encodes to 43 characters without padding
      expect(challenge.length).to eq(43)
    end

    it 'uses SHA256 hashing' do
      # Known test vector
      verifier = 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
      expected_challenge = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM'

      challenge = described_class.generate_code_challenge(verifier)
      expect(challenge).to eq(expected_challenge)
    end

    context 'with empty verifier' do
      it 'raises error for empty string' do
        expect { described_class.generate_code_challenge('') }.to raise_error(
          ArgumentError, /Code verifier must be between 43 and 128 characters/
        )
      end
    end

    context 'with special characters' do
      it 'raises error for verifiers with special characters' do
        verifier = 'test_verifier-with.special/chars+1239834829432='

        expect { described_class.generate_code_challenge(verifier) }.to raise_error(
          ArgumentError, /Code verifier contains invalid characters/
        )
      end
    end
  end
end
