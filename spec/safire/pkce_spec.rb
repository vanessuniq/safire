require 'spec_helper'

RSpec.describe Safire::PKCE do
  let(:pkce) { described_class.new }

  describe '#initialize' do
    it 'generates a code verifier and code challenge' do
      expect(pkce.code_verifier).not_to be_nil
      expect(pkce.code_challenge).not_to be_nil
      expect(pkce.code_challenge_method).to eq('S256')
    end
  end

  describe '#auth_params' do
    it 'returns the correct PKCE parameters for authorization flow' do
      auth_params = pkce.auth_params

      expect(auth_params).to include(
        code_challenge: pkce.code_challenge,
        code_challenge_method: 'S256'
      )
    end
  end
end
