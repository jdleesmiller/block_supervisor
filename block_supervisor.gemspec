# -*- encoding: utf-8 -*-
lib = File.expand_path('../lib/', __FILE__)
$:.unshift lib unless $:.include?(lib)
 
require 'block_supervisor/version'
 
Gem::Specification.new do |s|
  s.name              = 'block_supervisor'
  s.version           = BlockSupervisor::VERSION
  s.platform          = Gem::Platform::RUBY
  s.authors           = ['John Lees-Miller']
  s.email             = ['jdleesmiller@gmail.com']
  s.homepage          = 'http://github.com/jdleesmiller/block_supervisor'
  s.summary           = %q{Run a block with limited syscalls, resources and file handles.}
  s.description       = %q{Run a block in a child process with a restricted set of syscalls (using ptrace), a restricted set of file descriptors, and fixed resource limits (using rlimits). Only works on Linux.}

  s.rubyforge_project = 'block_supervisor'

  s.add_runtime_dependency 'syscalls', '~> 1.0.0'

  s.files       = Dir.glob('lib/**/*.rb') +
                  Dir.glob('ext/**/*{.rb,.c,.h}') + %w(README.rdoc)
  s.test_files  = Dir.glob('test/*_test.rb')
  s.extensions  = ["ext/block_supervisor/extconf.rb"]

  s.rdoc_options = [
    "--main",    "README.rdoc",
    "--title",   "#{s.full_name} Documentation"]
  s.extra_rdoc_files << "README.rdoc"
end

