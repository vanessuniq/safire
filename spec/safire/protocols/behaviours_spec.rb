require 'spec_helper'

RSpec.describe Safire::Protocols::Behaviours do
  subject(:instance) { Class.new { include Safire::Protocols::Behaviours }.new }

  %i[
    server_metadata authorization_url request_access_token
    refresh_token token_response_valid? register_client
  ].each do |method|
    it "##{method} raises NotImplementedError by default" do
      expect { instance.public_send(method) }.to raise_error(NotImplementedError)
    end
  end
end
