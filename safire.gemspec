# safire.gemspec
require_relative 'lib/safire/version'

Gem::Specification.new do |spec|
  spec.name                  = 'safire'
  spec.version               = Safire::VERSION
  spec.authors               = ['Vanessa Fotso']
  spec.email                 = ['vanessuniq@gmail.com']
  spec.summary               = 'SMART App Launch and UDAP implementation for Ruby'
  spec.description           = 'A Ruby gem implementing the SMART App Launch 2.2.0 specification and UDAP Security ' \
                               'protocol for healthcare client applications. It supports OAuth 2.0 authorization ' \
                               'against HL7 FHIR servers, including PKCE, private_key_jwt assertions (RS384 and ' \
                               'ES384), confidential client flows, and the Backend Services system-to-system ' \
                               '(client_credentials) grant.'
  spec.homepage              = 'https://github.com/vanessuniq/safire'
  spec.license               = 'Apache-2.0'
  spec.required_ruby_version = Gem::Requirement.new('>= 4.0.2')

  spec.metadata['source_code_uri']   = spec.homepage
  spec.metadata['changelog_uri']     = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata['documentation_uri'] = 'https://vanessuniq.github.io/safire'
  spec.metadata['rubygems_mfa_required'] = 'true'

  spec.files = Dir.chdir(__dir__) do
    `git ls-files -z`.split("\x0").reject do |f|
      (File.expand_path(f) == __FILE__) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ examples/ .git .github appveyor .vale])
    end
  end
  spec.bindir = 'exe'
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ['lib']

  # Runtime deps
  spec.add_dependency 'activesupport', '~> 8.0.0'
  spec.add_dependency 'addressable', '~> 2.8'
  spec.add_dependency 'faraday', '~> 2.14'
  spec.add_dependency 'faraday-follow_redirects', '~> 0.4'
  spec.add_dependency 'jwt', '~> 2.8'
end
