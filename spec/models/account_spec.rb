RSpec.describe Account, type: :model do
  it "retrieves a note belonging to the selected synthetic account" do
    account = Account.create!(name: "Synthetic north account")
    note = account.notes.create!(title: "Synthetic north note")

    expect(account.note(note.id).title).to eq("Synthetic north note")
  end

  it "does not retrieve another account's note" do
    north = Account.create!(name: "Synthetic north account")
    south = Account.create!(name: "Synthetic south account")
    other = south.notes.create!(title: "Synthetic south note")

    expect { north.note(other.id) }.to raise_error(ActiveRecord::RecordNotFound)
  end
end
