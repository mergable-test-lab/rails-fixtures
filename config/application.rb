require_relative "boot"
require "rails"
require "active_record/railtie"
require "action_controller/railtie"
require "rails/test_unit/railtie"
Bundler.require(*Rails.groups)

module SyntheticRailsFixtures
  class Application < Rails::Application
    config.load_defaults 8.0
    config.api_only = true
    config.eager_load = false
    config.hosts = ["www.example.com", "localhost", "127.0.0.1"]
  end
end
