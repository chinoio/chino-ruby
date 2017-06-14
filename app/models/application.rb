class Application < ApplicationRecord
    validates :app_id, presence: true
    validates :app_name, presence: true
    validates :app_secret, presence: true
    validates :grant_type, presence: true
end
