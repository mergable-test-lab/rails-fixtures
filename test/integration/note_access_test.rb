require "test_helper"

class NoteAccessTest < ActionDispatch::IntegrationTest
  test "a selected synthetic account reads only its own notes" do
    north = Account.create!(name: "Synthetic north account")
    south = Account.create!(name: "Synthetic south account")
    own = north.notes.create!(title: "Synthetic north note")
    other = south.notes.create!(title: "Synthetic south note")

    get "/accounts/#{north.id}/notes/#{own.id}"
    assert_response :success
    assert_equal({ "title" => "Synthetic north note" }, response.parsed_body)

    get "/accounts/#{north.id}/notes/#{other.id}"
    assert_response :not_found
    assert_equal({ "error" => "not_found" }, response.parsed_body)
  end

  test "a missing note has the same public not-found response" do
    account = Account.create!(name: "Synthetic empty account")

    get "/accounts/#{account.id}/notes/999999"

    assert_response :not_found
    assert_equal({ "error" => "not_found" }, response.parsed_body)
  end
end
