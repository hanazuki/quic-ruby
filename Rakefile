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
end

task default: %i[clobber compile test standard]
