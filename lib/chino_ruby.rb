require "base64"
require "uri"
require "net/https"
require "active_model"
require "json"
require "yaml"
require "digest"

#------------------------------CHINO ERRORS-----------------------------------#
#Class for defining common errors
class ChinoError < RuntimeError
  attr_accessor :http_response, :error, :user_error

  def initialize(error, http_response=nil, user_error=nil)
    @error = error
    @http_response = http_response
    @user_error = user_error
  end

  def to_s
    return "#{user_error} (#{error})" if user_error
    "#{error}"
  end
end

#Class for defining auth errors
class ChinoAuthError < ChinoError
end

require_relative "chino_ruby/classes"

# Class which contains every Chino.io resource as objects. In this way if you create a 'client' variable of this class,
# it will contain every function for the creation, update, retrieval... of every resource.
# Every function is easily accessible as follow:
#   name_of_the_client_variable.name_of_the_resource.name_of_the_function()
# Example of the creation of a Repository
#   @client = ChinoAPI.new(...)
#   @client.repositories.create_repository(...)
class ChinoAPI < ChinoRuby::CheckValues

    attr_accessor :applications, :auth, :repositories, :schemas, :documents, :user_schemas, :users, :groups, :collections, :permissions, :search, :blobs

    # Use this function to initialize your client variable
    # * customer_id: your customer id value
    # * customer_key: your customer key value
    # * host_url: the url of the server, use 'https://api.test.chino.io/v1' for development and 'https://api.chino.io/v1' for the production
    def initialize(customer_id, customer_key, host_url)
        check_string(customer_id)
        check_string(customer_key)
        check_string(host_url)
        @customer_id = customer_id
        @customer_key = customer_key
        @host_url = host_url
        @applications = ChinoRuby::Applications.new(@customer_id, @customer_key, @host_url)
        @auth = ChinoRuby::Auth.new(@customer_id, @customer_key, @host_url)
        @repositories = ChinoRuby::Repositories.new(@customer_id, @customer_key, @host_url)
        @schemas = ChinoRuby::Schemas.new(@customer_id, @customer_key, @host_url)
        @documents = ChinoRuby::Documents.new(@customer_id, @customer_key, @host_url)
        @user_schemas = ChinoRuby::UserSchemas.new(@customer_id, @customer_key, @host_url)
        @users = ChinoRuby::Users.new(@customer_id, @customer_key, @host_url)
        @groups = ChinoRuby::Groups.new(@customer_id, @customer_key, @host_url)
        @collections = ChinoRuby::Collections.new(@customer_id, @customer_key, @host_url)
        @permissions = ChinoRuby::Permissions.new(@customer_id, @customer_key, @host_url)
        @search = ChinoRuby::Search.new(@customer_id, @customer_key, @host_url)
        @blobs = ChinoRuby::Blobs.new(@customer_id, @customer_key, @host_url)
    end
end

#---------------------------CHINO SEARCH OPTIONS------------------------------#
class ChinoSortOption < ChinoRuby::SortOption
end
class ChinoFilterOption < ChinoRuby::FilterOption
end