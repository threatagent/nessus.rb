# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'nessus/version'

Gem::Specification.new do |spec|
  spec.name          = 'nessus'
  spec.version       = Nessus::VERSION
  spec.authors       = ['Erran Carey', 'Marcus J. Carey']
  spec.email         = ['me@errancarey.com', 'mjc@threatagent.com']
  spec.description   = %q{A Ruby client for the Nessus 5.x JSON REST API}
  spec.summary       = %q{A Ruby client for the Nessus 5.x JSON REST API. UPDATE_ME}
  spec.homepage      = 'https://github.com/threatagent/nessus.rb'
  spec.license       = 'MIT'

  spec.files         = `git ls-files`.split($/)
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  spec.add_development_dependency 'bundler', '~> 1.3'
  spec.add_development_dependency 'rake'

  spec.add_runtime_dependency     'faraday'
end
