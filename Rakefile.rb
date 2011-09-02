begin
  require 'rubygems'
  require 'bundler/setup'
  require 'gemma'

  Gemma::RakeTasks.with_gemspec_file 'block_supervisor.gemspec'
rescue LoadError
  puts 'Install gemma (sudo gem install gemma) for more rake tasks.'
end

NAME = 'block_supervisor'

file "lib/#{NAME}/#{NAME}.so" => Dir.glob("ext/#{NAME}/*{.rb,.c,.h}") do
  Dir.chdir("ext/#{NAME}") do
    ruby "extconf.rb"
    sh "make"
  end
  cp "ext/#{NAME}/#{NAME}.so", "lib/#{NAME}"
end

task :test => "lib/#{NAME}/#{NAME}.so"

CLEAN.include('ext/**/*{.o,.log,.so}')
CLEAN.include('ext/**/Makefile')
CLOBBER.include('lib/**/*.so')

task :default => :test

