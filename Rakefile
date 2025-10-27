require 'bundler/gem_tasks'
require 'rspec/core/rake_task'
require 'rubocop/rake_task'
require 'yard'

RSpec::Core::RakeTask.new(:spec)
RuboCop::RakeTask.new
YARD::Rake::YardocTask.new

task default: %i[spec rubocop]

desc 'Setup development environment'
task :setup do
  sh 'bin/setup'
  puts 'Development environment ready!'
end

desc 'Run security audit'
task :audit do
  sh 'bundle exec bundler-audit check --update'
end

desc 'Generate documentation'
task :docs do
  sh 'bin/docs'
end
