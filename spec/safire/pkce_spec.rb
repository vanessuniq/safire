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

    it 'matches the RFC 7636 Appendix B S256 test vector' do
      # RFC 7636 Appendix B known test vector
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

    context 'with a non-String verifier' do
      {
        'nil' => nil,
        'an Integer' => 1_234_567,
        'a Symbol of valid length' => ('a' * 43).to_sym,
        'an Array' => ['a'] * 43
      }.each do |description, verifier|
        it "raises ArgumentError naming the class for #{description}" do
          expect { described_class.generate_code_challenge(verifier) }.to raise_error(
            ArgumentError, "Code verifier must be a String, got #{verifier.class}"
          )
        end
      end

      it 'does not echo the verifier value in the error message' do
        verifier = ('s3cr3t' * 8).to_sym

        expect { described_class.generate_code_challenge(verifier) }.to raise_error(ArgumentError) { |error|
          expect(error.message).not_to include(verifier.to_s)
        }
      end
    end

    context 'with length boundaries' do
      it 'rejects a 42-character verifier' do
        expect { described_class.generate_code_challenge('a' * 42) }.to raise_error(
          ArgumentError, 'Code verifier must be between 43 and 128 characters long, got 42'
        )
      end

      it 'accepts a 43-character verifier' do
        expect(described_class.generate_code_challenge('a' * 43)).to match(/\A[A-Za-z0-9_-]{43}\z/)
      end

      it 'accepts a 128-character verifier' do
        expect(described_class.generate_code_challenge('a' * 128)).to match(/\A[A-Za-z0-9_-]{43}\z/)
      end

      it 'rejects a 129-character verifier' do
        expect { described_class.generate_code_challenge('a' * 129) }.to raise_error(
          ArgumentError, 'Code verifier must be between 43 and 128 characters long, got 129'
        )
      end
    end

    context 'with allowed characters' do
      it 'accepts a verifier containing every unreserved character' do
        verifier = [*'A'..'Z', *'a'..'z', *'0'..'9', '-', '.', '_', '~'].join

        expect(described_class.generate_code_challenge(verifier)).to match(/\A[A-Za-z0-9_-]{43}\z/)
      end

      it 'accepts a String subclass' do
        verifier = Class.new(String).new('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')

        expect(described_class.generate_code_challenge(verifier)).to eq('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM')
      end

      it 'accepts a frozen verifier' do
        expect(described_class.generate_code_challenge(('a' * 43).freeze)).to be_a(String)
      end
    end

    context 'with disallowed characters' do
      {
        'a space' => ' ',
        'a plus sign' => '+',
        'a slash' => '/',
        'an equals sign' => '=',
        'a percent sign' => '%',
        'a trailing newline' => "\n",
        'a non-ASCII character' => 'é'
      }.each do |description, char|
        it "rejects a verifier containing #{description}" do
          verifier = ('a' * 42) + char

          expect { described_class.generate_code_challenge(verifier) }.to raise_error(
            ArgumentError, /Code verifier contains invalid characters/
          )
        end
      end
    end

    context 'with non-ASCII or invalid encodings' do
      {
        'multibyte UTF-8 characters' => 'é' * 43,
        'invalid UTF-8 bytes' => ("\xFF" * 43).dup.force_encoding(Encoding::UTF_8),
        'high binary bytes' => ("\xFF" * 43).b,
        'an ASCII-incompatible encoding' => ('a' * 43).encode(Encoding::UTF_16LE)
      }.each do |description, verifier|
        it "rejects #{description} with the invalid characters error" do
          expect { described_class.generate_code_challenge(verifier) }.to raise_error(
            ArgumentError, /Code verifier contains invalid characters/
          )
        end
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
