require "test_helper"

class AccountTest < ActiveSupport::TestCase
  test "an account retrieves its own note by identifier" do
    account = Account.create!(name: "Synthetic north account")
    note = account.notes.create!(title: "Synthetic north note")

    assert_equal "Synthetic north note", account.note(note.id).title
  end

  test "an account cannot retrieve a note belonging to another account" do
    north = Account.create!(name: "Synthetic north account")
    south = Account.create!(name: "Synthetic south account")
    other = south.notes.create!(title: "Synthetic south note")

    assert_raises(ActiveRecord::RecordNotFound) { north.note(other.id) }
  end
end
