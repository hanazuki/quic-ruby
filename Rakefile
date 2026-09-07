# frozen_string_literal: true

require "bundler/gem_tasks"
require "minitest/test_task"

Minitest::TestTask.create

require "standard/rake"

require "rake/extensiontask"

task build: :compile

GEMSPEC = Gem::Specification.load("quic.gemspec")

Rake::ExtensionTask.new("quic", GEMSPEC) do |ext|
  ext.lib_dir = "lib/quic"
  ext.cross_compile = true
  ext.cross_platform = ["x86_64-linux-gnu"]

  # Adjustments specific to the precompiled (x86_64-linux-gnu) gem.
  ext.cross_compiling do |spec|
    # The prebuilt .so is bundled, so no recompilation at install time.
    spec.extensions = []
    # Restrict to the Ruby ABIs we actually build .so files for (3.4.x / 4.0.x).
    spec.required_ruby_version = [">= 3.4.0", "< 4.1.dev"]
    # mini_portile2 only runs during a source build, which never happens for the
    # precompiled gem, so drop it from the platform gem's dependencies.
    spec.dependencies.reject! { |dep| dep.name == "mini_portile2" }
  end
end

# Build the precompiled x86_64-linux gem inside rake-compiler-dock. The require is
# guarded so the Rakefile still loads when rake-compiler-dock isn't installed.
begin
  require "rake_compiler_dock"
rescue LoadError
  # rake-compiler-dock not available: just skip defining the gem:x86_64-linux task.
end

if defined?(RakeCompilerDock)
  namespace :gem do
    desc "Build precompiled x86_64-linux-gnu fat gem inside rake-compiler-dock"
    task "x86_64-linux-gnu" do
      # Single-quoted heredoc: the shell ($-substitution, backslashes) must reach
      # the container verbatim, with no Ruby interpolation/escape processing.
      #
      # - BUNDLE_FROZEN keeps the container's bundler from rewriting the mounted
      #   Gemfile.lock, making the release build reproducible.
      # - RUBY_CC_VERSION is derived from the image's bundled rubies, picking the
      #   3.4.x and 4.0.x entries so the fat gem carries lib/quic/3.4 and 4.0 .so.
      #   Patch versions track the image, so they are never hardcoded. set -e only
      #   sees the exit status of the last pipeline element (paste), so an empty
      #   match has to be caught explicitly or we would ship a gem without any .so.
      RakeCompilerDock.sh <<~'CMD', platform: "x86_64-linux-gnu"
        set -e
        BUNDLE_FROZEN=true bundle install
        cc=$(echo "$RUBY_CC_VERSION" | tr ':' '\n' | grep -E '^(3\.4|4\.0)\.' | paste -sd: -)
        [ -n "$cc" ] || { echo "no 3.4.x / 4.0.x cross rubies found in RUBY_CC_VERSION=$RUBY_CC_VERSION" >&2; exit 1; }
        echo "Building for RUBY_CC_VERSION=$cc"
        RUBY_CC_VERSION="$cc" bundle exec rake cross native gem
      CMD
    end
  end
end

task default: %i[clobber compile test standard]
