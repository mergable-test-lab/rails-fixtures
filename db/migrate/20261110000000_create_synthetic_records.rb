class CreateSyntheticRecords < ActiveRecord::Migration[8.0]
  def change
    create_table :accounts do |table|
      table.string :name, null: false
    end

    create_table :notes do |table|
      table.references :account, null: false, foreign_key: true
      table.string :title, null: false
    end
  end
end
