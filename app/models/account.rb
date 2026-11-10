class Account < ApplicationRecord
  has_many :notes, dependent: :destroy

  def note(identifier)
    notes.find(identifier)
  end
end
