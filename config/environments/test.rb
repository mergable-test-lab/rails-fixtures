Rails.application.configure do
  config.cache_classes = true
  config.action_dispatch.show_exceptions = :rescuable
  config.active_support.deprecation = :stderr
end
