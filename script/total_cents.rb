require 'json'

items = JSON.parse($stdin.read).fetch('items')
total_cents = items.sum { |item| item.fetch('cents') * item.fetch('quantity') }
puts JSON.generate('total_cents' => total_cents)
