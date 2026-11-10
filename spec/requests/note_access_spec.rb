RSpec.describe "Synthetic note access", type: :request do
  it "returns the selected account's note" do
    account = Account.create!(name: "Synthetic north account")
    note = account.notes.create!(title: "Synthetic north note")

    get "/accounts/#{account.id}/notes/#{note.id}"

    expect(response).to have_http_status(:ok)
    expect(response.parsed_body).to eq("title" => "Synthetic north note")
  end

  it "returns not found for another account's note" do
    north = Account.create!(name: "Synthetic north account")
    south = Account.create!(name: "Synthetic south account")
    other = south.notes.create!(title: "Synthetic south note")

    get "/accounts/#{north.id}/notes/#{other.id}"

    expect(response).to have_http_status(:not_found)
    expect(response.parsed_body).to eq("error" => "not_found")
  end

  it "returns the same not-found response for a missing note" do
    account = Account.create!(name: "Synthetic empty account")

    get "/accounts/#{account.id}/notes/999999"

    expect(response).to have_http_status(:not_found)
    expect(response.parsed_body).to eq("error" => "not_found")
  end
end
