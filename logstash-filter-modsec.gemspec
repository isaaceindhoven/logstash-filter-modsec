Gem::Specification.new do |s|
  s.name          = 'logstash-filter-modsec'
  s.version       = '0.1.0'
  s.licenses      = ['Nonstandard']
  s.summary       = 'This is a filter plugin for Logstash to parse ModSecurity audit log files.'
  s.homepage      = 'https://github.com/isaaceindhoven/logstash-filter-modsec'
  s.authors       = ['Nick Heskes']
  s.email         = 'nick.heskes@isaac.nl'
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','CONTRIBUTORS','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_development_dependency 'logstash-devutils'
end
