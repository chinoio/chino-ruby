class CreateApplications < ActiveRecord::Migration[5.1]
  def change
    create_table :applications do |t|
      t.string :app_secret
      t.string :grant_type
      t.string :app_name
      t.string :redirect_url
      t.string :app_id

      t.timestamps
    end
  end
end
