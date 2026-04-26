source 'https://rubygems.org'

ruby '4.0.3'

gemspec

group :development, :test do
  gem 'bundler-audit', '~> 0.9'
  gem 'debug'
  gem 'pry'
  gem 'pry-byebug'
  gem 'rspec', '~> 3.12'
  gem 'rubocop', '~> 1.57'
  gem 'rubocop-rspec', '~> 3.0', require: false
  gem 'timecop', '~> 0.9'
end

group :development do
  gem 'yard', '~> 0.9'
end

group :test do
  gem 'dotenv', '~> 3.0'
  gem 'simplecov', require: false
  gem 'simplecov-cobertura', require: false
  gem 'webmock', '~> 3.18'
end
