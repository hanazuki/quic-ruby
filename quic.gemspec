# frozen_string_literal: true

require_relative "lib/quic/version"

Gem::Specification.new do |spec|
  spec.name = "quic"
  spec.version = Quic::VERSION
  spec.authors = ["Yusuke Nakamura"]
  spec.email = ["yusuke1994525@gmail.com"]

  spec.summary = "Thin Ruby binding around ngtcp2 for the QUIC transport protocol, with LibreSSL as the TLS backend."
  spec.description = "A thin Ruby binding around ngtcp2 for the QUIC transport protocol, with LibreSSL as the TLS backend. " \
    "Both are vendored via mini_portile2 at install time; no system libraries required. " \
    "The API is intentionally optimized for synchronous I/O and String-based buffers. " \
    "Public API is not yet stable."
  spec.homepage = "https://github.com/unasuke/quic-ruby"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.2.0"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/unasuke/quic-ruby"
  spec.metadata["changelog_uri"] = "https://github.com/unasuke/quic-ruby/blob/main/CHANGELOG.md"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ Gemfile .gitignore test/ .github/ .standard.yml])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]
  spec.extensions = ["ext/quic/extconf.rb"]

  # Uncomment to register a new dependency of your gem
  # spec.add_dependency "example-gem", "~> 1.0"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
