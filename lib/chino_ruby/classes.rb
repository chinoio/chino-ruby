module ChinoRuby
  QUERY_DEFAULT_LIMIT = 100


  class CheckValues

    # This function is used to check if a parameter passed to a function is a string, otherwise it raises an error
    def check_string(value)
      if not value.is_a?(String)
        raise ArgumentError, "{#value} must be a String, got #{value.inspect}"
      end
    end

    # This function is used to check if a parameter passed to a function is an integer, otherwise it raises an error
    def check_int(value)
      if not value.is_a?(Integer)
        raise ArgumentError, "{#value} must be a Int, got #{value.inspect}"
      end
    end

    # This function is used to check if a parameter passed to a function is a boolean, otherwise it raises an error
    def check_boolean(value)
      if not !!value == value
        raise ArgumentError, "{#value} must be a Boolean, got #{value.inspect}"
      end
    end

    # This function is used to check if a parameter passed to a function can be converted to json, otherwise it raises an error
    def check_json(value)
      if not value.respond_to?(:to_json)
        raise ArgumentError, "{#value} cannot be converted to json!"
      end
    end
  end

# Class which defines the fields for the creation of a Schema or a UserSchema
  class Field < CheckValues
    attr_accessor :type, :name, :indexed

    # * type: type of the field in the Schema/UserSchema. Ex: 'string'
    # * name: name of the field in the Schema/UserSchema
    # * indexed: if true, the field will be indexed on the server. That means it can be used to make a search request
    def initialize(type, name, indexed)
      check_string(type)
      check_string(name)
      check_boolean(indexed)
      self.type = type
      self.name = name
      self.indexed = indexed
    end

    # Returns the values as a json
    def to_json
      return {"type": type, "name": name, "indexed": indexed}.to_json
    end
  end

# Base class of every resource class. It contains the functions for the GET, POST, PUT, PATCH and DELETE requests
  class ChinoBaseAPI < CheckValues

    # Used to inizialize a customer or a user. If you want to authenticate a user, simply pass "" as the customer_id
    def initialize(customer_id, customer_key, host_url)
      if customer_id == ""
        @customer_id = "Bearer "
      end
      @customer_id = customer_id
      @customer_key = customer_key
      @host_url = host_url
    end

    #returns the uri with the proper params if specified
    def return_uri(path, limit=nil, offset=nil, full_document=nil)
      uri = URI(@host_url+path)
      if limit!=nil && offset!=nil
        if full_document!=nil
          params = { :"full_document" => true, :"limit" => limit, :"offset" => offset}
          uri.query = URI.encode_www_form(params)
        else
          params = { "limit" => limit, :"offset" => offset}
          uri.query = URI.encode_www_form(params)
        end
      end
      uri
    end

    #base function to GET a resource with the proper params if specified
    def get_resource(path, limit=nil, offset=nil, full_document=nil)
      check_string(path)
      if (limit==nil) && (offset==nil)
        uri = return_uri(path)
      elsif full_document==nil
        uri = return_uri(path, limit, offset)
      else
        uri = return_uri(path, limit, offset, full_document)
      end
      req = Net::HTTP::Get.new(uri.path)
      if @customer_id == "Bearer "
        req.add_field("Authorization", @customer_id+@customer_key)
      else
        req.basic_auth @customer_id, @customer_key
      end
      res = Net::HTTP.start(uri.hostname, uri.port, :use_ssl => true) {|http|
        http.request(req)
      }
      parse_response(res)['data']
    end

    #base function to POST a resource with the proper params if specified
    def post_resource(path, data=nil, limit=nil, offset=nil, full_document=nil)
      check_string(path)
      if (limit==nil) && (offset==nil)
        uri = return_uri(path)
      elsif full_document==nil
        uri = return_uri(path, limit, offset)
      else
        uri = return_uri(path, limit, offset, full_document)
      end
      req = Net::HTTP::Post.new(uri.path)
      if @customer_id == "Bearer "
        req.add_field("Authorization", @customer_id+@customer_key)
      else
        req.basic_auth @customer_id, @customer_key
      end
      if data!=nil
        req.body = data
      end
      res = Net::HTTP.start(uri.hostname, uri.port, :use_ssl => true) {|http|
        http.request(req)
      }
      if data!=nil
        parse_response(res)['data']
      else
        JSON.parse(parse_response(res).to_json)['result']
      end
    end

    #base function to POST a resource with string result
    def post_resource_with_string_result(path, data)
      check_string(path)
      uri = return_uri(path)
      req = Net::HTTP::Post.new(uri.path)
      if @customer_id == "Bearer "
        req.add_field("Authorization", @customer_id+@customer_key)
      else
        req.basic_auth @customer_id, @customer_key
      end
      req.body = data
      res = Net::HTTP.start(uri.hostname, uri.port, :use_ssl => true) {|http|
        http.request(req)
      }
      JSON.parse(parse_response(res).to_json)['result']
    end

    #base function to PUT a resource
    def put_resource(path, data)
      check_string(path)
      uri = return_uri(path)
      req = Net::HTTP::Put.new(uri.path)
      if @customer_id == "Bearer "
        req.add_field("Authorization", @customer_id+@customer_key)
      else
        req.basic_auth @customer_id, @customer_key
      end
      req.body = data
      res = Net::HTTP.start(uri.hostname, uri.port, :use_ssl => true) {|http|
        http.request(req)
      }
      parse_response(res)['data']
    end

    #base function to PATCH a resource
    def patch_resource(path, data)
      check_string(path)
      uri = return_uri(path)
      req = Net::HTTP::Patch.new(uri.path)
      if @customer_id == "Bearer "
        req.add_field("Authorization", @customer_id+@customer_key)
      else
        req.basic_auth @customer_id, @customer_key
      end
      req.body = data
      res = Net::HTTP.start(uri.hostname, uri.port, :use_ssl => true) {|http|
        http.request(req)
      }
      parse_response(res)['data']
    end

    #base function to DELETE a resource
    def delete_resource(path, force)
      check_string(path)
      check_boolean(force)
      if force
        uri = return_uri(path+"?force=true")
      else
        uri = return_uri(path)
      end
      req = Net::HTTP::Delete.new(uri)
      if @customer_id == "Bearer "
        req.add_field("Authorization", @customer_id+@customer_key)
      else
        req.basic_auth @customer_id, @customer_key
      end
      res = Net::HTTP.start(uri.hostname, uri.port, :use_ssl => true) {|http|
        http.request(req)
      }
      JSON.parse(parse_response(res).to_json)['result']
    end

    #base function to parse the response and raise "chino" errors if problems occurred
    def parse_response(response, raw=false)
      if response.is_a?(Net::HTTPServerError)
        raise ChinoError.new("Chino Server Error: #{response} - #{response.body}", response)
      elsif response.is_a?(Net::HTTPUnauthorized)
        d = JSON.parse(response.body)
        raise ChinoAuthError.new("Chino authentication error: #{d['message']}", response)
      elsif !response.is_a?(Net::HTTPSuccess)
        begin
          d = JSON.parse(response.body)
        rescue
          raise ChinoError.new("Chino Server Error: body=#{response.body}", response)
        end
        if d['user_error'] and d['error']
          raise ChinoError.new(d['error'], response, d['user_error'])  #user_error is translated
        elsif d['error']
          raise ChinoError.new(d['error'], response)
        else
          raise ChinoError.new(response.body, response)
        end
      end

      return response.body if raw

      begin
        return JSON.parse(response.body)
      rescue JSON::ParserError
        raise ChinoError.new("Unable to parse JSON response: #{response.body}", response)
      end
    end
  end

#------------------------------APPLICATIONS-----------------------------------#

  class Application
    include ActiveModel::Serializers::JSON

    attr_accessor :app_name, :app_id, :app_secret, :grant_type, :redirect_url, :client_type

    def attributes=(hash)
      hash.each do |key, value|
        send("#{key}=", value)
      end
    end

    def attributes
      instance_values
    end
  end

  class GetApplicationsResponse
    include ActiveModel::Serializers::JSON

    attr_accessor :count, :total_count, :limit, :offset, :applications

    def attributes=(hash)
      hash.each do |key, value|
        send("#{key}=", value)
      end
    end

    def attributes
      instance_values
    end
  end

  class Applications < ChinoBaseAPI

    def get_application(app_id)
      check_string(app_id)
      app = Application.new
      app.from_json(get_resource("/auth/applications/#{app_id}").to_json, true)
      app
    end

    def list_applications(limit=nil, offset=nil)
      apps = GetApplicationsResponse.new
      if limit==nil && offset==nil
        apps.from_json(get_resource("/auth/applications", ChinoRuby::QUERY_DEFAULT_LIMIT, 0).to_json)
      else
        apps.from_json(get_resource("/auth/applications", limit, offset).to_json)
      end
      as = apps.applications
      apps.applications = []
      as.each do |a|
        app = Application.new
        app.app_id = a['app_id']
        app.app_name = a['app_name']
        apps.applications.push(app)
      end
      apps
    end

    def create_application(name, grant_type, redirect_url)
      check_string(name)
      check_string(grant_type)
      check_string(redirect_url)
      data = {"name": name, "grant_type": grant_type, "redirect_url": redirect_url}.to_json
      app = Application.new
      app.from_json(post_resource("/auth/applications", data).to_json, true)
      app
    end

    def update_application(app_id, name, grant_type, redirect_url)
      check_string(name)
      check_string(grant_type)
      check_string(redirect_url)
      check_string(app_id)
      data = {"name": name, "grant_type": grant_type, "redirect_url": redirect_url}.to_json
      app = Application.new
      app.from_json(put_resource("/auth/applications/#{app_id}", data).to_json, true)
      app
    end

    def delete_application(app_id, force)
      check_string(app_id)
      check_boolean(force)
      delete_resource("/auth/applications/#{app_id}", force)
    end
  end

#------------------------------AUTH-----------------------------------#

  class LoggedUser
    include ActiveModel::Serializers::JSON

    attr_accessor :access_token, :token_type, :expires_in, :refresh_token, :scope

    def attributes=(hash)
      hash.each do |key, value|
        send("#{key}=", value)
      end
    end

    def attributes
      instance_values
    end
  end

  class Auth < ChinoBaseAPI

    def login_password(username, password, application_id, application_secret)
      check_string(username)
      check_string(password)
      check_string(application_id)
      check_string(application_secret)
      uri = return_uri("/auth/token/")
      req = Net::HTTP::Post.new(uri.path)
      req.basic_auth application_id, application_secret
      req.set_form_data([["username", username], ["password", password], ["grant_type", "password"]])
      res = Net::HTTP.start(uri.hostname, uri.port, :use_ssl => true) {|http|
        http.request(req)
      }
      usr = LoggedUser.new
      usr.from_json((parse_response(res)['data']).to_json)
      usr
    end

    def login_authentication_code(code, redirect_url, application_id, application_secret)
      check_string(code)
      check_string(redirect_url)
      check_string(application_id)
      check_string(application_secret)
      uri = return_uri("/auth/token/")
      req = Net::HTTP::Post.new(uri.path)
      req.basic_auth application_id, application_secret
      req.set_form_data([["code", code], ["redirect_uri", redirect_url], ["grant_type", "authorization_code"], ["scope", "read write"], ["client_id", application_id], ["client_secret", application_secret]])
      res = Net::HTTP.start(uri.hostname, uri.port, :use_ssl => true) {|http|
        http.request(req)
      }
      usr = LoggedUser.new
      usr.from_json((parse_response(res)['data']).to_json)
      usr
    end

    def refresh_token(refresh_token, application_id, application_secret)
      check_string(refresh_token)
      check_string(application_id)
      check_string(application_secret)
      uri = return_uri("/auth/token/")
      req = Net::HTTP::Post.new(uri.path)
      req.basic_auth application_id, application_secret
      req.set_form_data([["refresh_token", refresh_token], ["client_id", application_id], ["client_secret", application_secret], ["grant_type", "refresh_token"]])
      res = Net::HTTP.start(uri.hostname, uri.port, :use_ssl => true) {|http|
        http.request(req)
      }
      usr = LoggedUser.new
      usr.from_json((parse_response(res)['data']).to_json)
      usr
    end

    def logout(token, application_id, application_secret)
      check_string(token)
      check_string(application_id)
      check_string(application_secret)
      uri = return_uri("/auth/revoke_token/")
      req = Net::HTTP::Post.new(uri.path)
      req.basic_auth application_id, application_secret
      req.set_form_data([["token", token], ["client_id", application_id], ["client_secret", application_secret]])
      res = Net::HTTP.start(uri.hostname, uri.port, :use_ssl => true) {|http|
        http.request(req)
      }
      parse_response(res)['result']

    end
  end

#------------------------------REPOSITORIES-----------------------------------#

  class Repository
    include ActiveModel::Serializers::JSON

    attr_accessor :repository_id, :description, :is_active, :last_update, :insert_date

    def attributes=(hash)
      hash.each do |key, value|
        send("#{key}=", value)
      end
    end

    def attributes
      instance_values
    end
  end

  class GetRepositoriesResponse
    include ActiveModel::Serializers::JSON

    attr_accessor :count, :total_count, :limit, :offset, :repositories

    def attributes=(hash)
      hash.each do |key, value|
        send("#{key}=", value)
      end
    end

    def attributes
      instance_values
    end
  end

  class Repositories < ChinoBaseAPI

    def get_repository(repo_id)
      check_string(repo_id)
      repo = Repository.new
      repo.from_json(get_resource("/repositories/#{repo_id}").to_json, true)
      repo
    end

    def list_repositories(limit=nil, offset=nil)
      repos = GetRepositoriesResponse.new
      if limit==nil && offset==nil
        repos.from_json(get_resource("/repositories", ChinoRuby::QUERY_DEFAULT_LIMIT, 0).to_json)
      else
        repos.from_json(get_resource("/repositories", limit, offset).to_json)
      end
      rs = repos.repositories
      repos.repositories = []
      rs.each do |r|
        repo = Repository.new
        repo.from_json(r.to_json)
        repos.repositories.push(repo)
      end
      repos
    end

    def create_repository(description)
      check_string(description)
      data = {"description": description}.to_json
      repo = Repository.new
      repo.from_json(post_resource("/repositories", data).to_json, true)
      repo
    end

    def update_repository(repository_id, description, is_active=nil)
      check_string(repository_id)
      check_string(description)
      if is_active.nil?
        data = {"description": description}.to_json
      else
        data = {"description": description, "is_active": is_active}.to_json
      end
      repo = Repository.new
      repo.from_json(put_resource("/repositories/#{repository_id}", data).to_json, true)
      repo
    end

    def delete_repository(repository_id, force)
      check_string(repository_id)
      check_boolean(force)
      delete_resource("/repositories/#{repository_id}", force)
    end
  end

#------------------------------USER SCHEMAS-----------------------------------#

  class UserSchema
    include ActiveModel::Serializers::JSON

    attr_accessor :user_schema_id, :description, :is_active, :last_update, :structure, :insert_date, :groups

    def attributes=(hash)
      hash.each do |key, value|
        send("#{key}=", value)
      end
    end

    def attributes
      instance_values
    end

    def getFields()
      structure['fields']
    end
  end

  class GetUserSchemasResponse
    include ActiveModel::Serializers::JSON

    attr_accessor :count, :total_count, :limit, :offset, :user_schemas

    def attributes=(hash)
      hash.each do |key, value|
        send("#{key}=", value)
      end
    end

    def attributes
      instance_values
    end
  end

  class UserSchemas < ChinoBaseAPI

    def get_user_schema(user_schema_id)
      check_string(user_schema_id)
      u = UserSchema.new
      u.from_json(get_resource("/user_schemas/#{user_schema_id}").to_json, true)
      u
    end

    def list_user_schemas(limit=nil, offset=nil)
      schemas = GetUserSchemasResponse.new
      if limit==nil && offset==nil
        schemas.from_json(get_resource("/user_schemas", ChinoRuby::QUERY_DEFAULT_LIMIT, 0).to_json)
      else
        schemas.from_json(get_resource("/user_schemas", limit, offset).to_json)
      end
      us = schemas.user_schemas
      schemas.user_schemas = []
      us.each do |u|
        schema = UserSchema.new
        schema.from_json(u.to_json)
        schemas.user_schemas.push(schema)
      end
      schemas
    end

    def create_user_schema(description, fields)
      check_string(description)
      check_json(fields)
      data = {"description": description, "structure": { "fields": fields}}.to_json
      schema = UserSchema.new
      schema.from_json(post_resource("/user_schemas", data).to_json, true)
      schema
    end

    def update_user_schema(user_schema_id, description, fields)
      check_string(user_schema_id)
      check_string(description)
      check_json(fields)
      data = {"description": description, "structure": { "fields": fields}}.to_json
      schema = UserSchema.new
      schema.from_json(put_resource("/user_schemas/#{user_schema_id}", data).to_json, true)
      schema
    end

    def delete_user_schema(user_schema_id, force)
      check_string(user_schema_id)
      check_boolean(force)
      delete_resource("/user_schemas/#{user_schema_id}", force)
    end
  end

#------------------------------USERS-----------------------------------#

  class User
    include ActiveModel::Serializers::JSON

    attr_accessor :username, :user_id, :schema_id, :is_active, :last_update, :user_attributes, :insert_date, :groups

    def attributes=(hash)
      hash.each do |key, value|
        if key=="attributes"
          @user_attributes = value
        else
          send("#{key}=", value)
        end
      end
    end

    def attributes
      instance_values
    end
  end

  class GetUsersResponse
    include ActiveModel::Serializers::JSON

    attr_accessor :count, :total_count, :limit, :offset, :users

    def attributes=(hash)
      hash.each do |key, value|
        send("#{key}=", value)
      end
    end

    def attributes
      instance_values
    end
  end

  class Users < ChinoBaseAPI

    def me
      u = User.new
      u.from_json(get_resource("/users/me").to_json, true)
      u
    end

    def get_user(user_id)
      check_string(user_id)
      u = User.new
      u.from_json(get_resource("/users/#{user_id}").to_json, true)
      u
    end

    def list_users(user_schema_id, limit=nil, offset=nil)
      check_string(user_schema_id)
      users = GetUsersResponse.new
      if limit==nil && offset==nil
        users.from_json(get_resource("/user_schemas/#{user_schema_id}/users", ChinoRuby::QUERY_DEFAULT_LIMIT, 0).to_json)
      else
        users.from_json(get_resource("/user_schemas/#{user_schema_id}/users", limit, offset).to_json)
      end
      us = users.users
      users.users = []
      us.each do |u|
        user = User.new
        user.from_json(u.to_json)
        users.users.push(user)
      end
      users
    end

    def create_user(user_schema_id, username, password, attributes)
      check_string(user_schema_id)
      check_string(username)
      check_string(password)
      check_json(attributes)
      data = {"username": username, "password": password, "attributes": attributes}.to_json
      user = User.new
      user.from_json(post_resource("/user_schemas/#{user_schema_id}/users", data).to_json, true)
      user
    end

    def update_user(user_id, username, password, attributes)
      check_string(user_id)
      check_string(username)
      check_string(password)
      check_json(attributes)
      data = {"username": username, "password": password, "attributes": attributes}.to_json
      user = User.new
      user.from_json(put_resource("/users/#{user_id}", data).to_json, true)
      user
    end

    def update_user_partial(user_id, attributes)
      check_string(user_id)
      check_json(attributes)
      data = {"attributes": attributes}.to_json
      user = User.new
      user.from_json(patch_resource("/users/#{user_id}", data).to_json, true)
      user
    end

    def delete_user(user_id, force)
      check_string(user_id)
      check_boolean(force)
      delete_resource("/users/#{user_id}", force)
    end
  end

#------------------------------GROUPS-----------------------------------#

  class Group
    include ActiveModel::Serializers::JSON

    attr_accessor :group_name, :group_id, :is_active, :last_update, :group_attributes, :insert_date

    def attributes=(hash)
      hash.each do |key, value|
        if key=="attributes"
          @group_attributes = value
        else
          send("#{key}=", value)
        end
      end
    end

    def attributes
      instance_values
    end
  end

  class GetGroupsResponse
    include ActiveModel::Serializers::JSON

    attr_accessor :count, :total_count, :limit, :offset, :groups

    def attributes=(hash)
      hash.each do |key, value|
        send("#{key}=", value)
      end
    end

    def attributes
      instance_values
    end
  end

  class Groups < ChinoBaseAPI

    def get_group(group_id)
      check_string(group_id)
      g = Group.new
      g.from_json(get_resource("/groups/#{group_id}").to_json, true)
      g
    end

    def list_groups(limit=nil, offset=nil)
      groups = GetGroupsResponse.new
      if limit==nil && offset==nil
        groups.from_json(get_resource("/groups", ChinoRuby::QUERY_DEFAULT_LIMIT, 0).to_json)
      else
        groups.from_json(get_resource("/groups", limit, offset).to_json)
      end
      gs = groups.groups
      groups.groups = []
      gs.each do |g|
        group = Group.new
        group.from_json(g.to_json)
        groups.groups.push(group)
      end
      groups
    end

    def create_group(group_name, attributes)
      check_string(group_name)
      check_json(attributes)
      data = {"group_name": group_name, "attributes": attributes}.to_json
      group = Group.new
      group.from_json(post_resource("/groups", data).to_json, true)
      group
    end

    def update_group(group_id, group_name, attributes)
      check_string(group_id)
      check_string(group_name)
      check_json(attributes)
      data = {"group_name": group_name, "attributes": attributes}.to_json
      group = Group.new
      group.from_json(put_resource("/groups/#{group_id}", data).to_json, true)
      group
    end

    def delete_group(group_id, force)
      check_string(group_id)
      check_boolean(force)
      delete_resource("/groups/#{group_id}", force)
    end

    def add_user_to_group(user_id, group_id)
      check_string(group_id)
      check_string(user_id)
      post_resource("/groups/#{group_id}/users/#{user_id}")
    end

    def add_user_schema_to_group(user_schema_id, group_id)
      check_string(group_id)
      check_string(user_schema_id)
      post_resource("/groups/#{group_id}/user_schemas/#{user_schema_id}")
    end

    def remove_user_from_group(user_id, group_id)
      check_string(group_id)
      check_string(user_id)
      delete_resource("/groups/#{group_id}/users/#{user_id}", false)
    end

    def remove_user_schema_from_group(user_schema_id, group_id)
      check_string(group_id)
      check_string(user_schema_id)
      delete_resource("/groups/#{group_id}/user_schemas/#{user_schema_id}", false)
    end
  end

#------------------------------SCHEMAS-----------------------------------#

  class Schema
    include ActiveModel::Serializers::JSON

    attr_accessor :repository_id, :schema_id, :description, :is_active, :last_update, :structure, :insert_date

    def attributes=(hash)
      hash.each do |key, value|
        send("#{key}=", value)
      end
    end

    def attributes
      instance_values
    end

    def getFields()
      structure['fields']
    end
  end

  class GetSchemasResponse
    include ActiveModel::Serializers::JSON

    attr_accessor :count, :total_count, :limit, :offset, :schemas

    def attributes=(hash)
      hash.each do |key, value|
        send("#{key}=", value)
      end
    end

    def attributes
      instance_values
    end
  end

  class Schemas < ChinoBaseAPI

    def get_schema(schema_id)
      check_string(schema_id)
      s = Schema.new
      s.from_json(get_resource("/schemas/#{schema_id}").to_json, true)
      s
    end

    def list_schemas(repository_id, limit=nil, offset=nil)
      check_string(repository_id)
      schemas = GetSchemasResponse.new
      if limit==nil && offset==nil
        schemas.from_json(get_resource("/repositories/#{repository_id}/schemas", ChinoRuby::QUERY_DEFAULT_LIMIT, 0).to_json)
      else
        schemas.from_json(get_resource("/repositories/#{repository_id}/schemas", limit, offset).to_json)
      end
      ss = schemas.schemas
      schemas.schemas = []
      ss.each do |s|
        schema = Schema.new
        schema.from_json(s.to_json)
        schemas.schemas.push(schema)
      end
      schemas
    end

    def create_schema(repository_id, description, fields)
      check_string(repository_id)
      check_string(description)
      check_json(fields)
      data = {"description": description, "structure": { "fields": fields}}.to_json
      schema = Schema.new
      schema.from_json(post_resource("/repositories/#{repository_id}/schemas", data).to_json, true)
      schema
    end

    def update_schema(schema_id, description, fields, is_active=nil)
      check_string(schema_id)
      check_string(description)
      check_json(fields)
      if is_active.nil?
        data = {"description": description, "structure": { "fields": fields}}.to_json
      else
        data = {"description": description, "structure": { "fields": fields}, "is_active": is_active}.to_json
      end
      schema = Schema.new
      schema.from_json(put_resource("/schemas/#{schema_id}", data).to_json, true)
      schema
    end

    def delete_schema(schema_id, force)
      check_string(schema_id)
      check_boolean(force)
      delete_resource("/schemas/#{schema_id}", force)
    end
  end

#------------------------------DOCUMENTS-----------------------------------#

  class Document
    include ActiveModel::Serializers::JSON

    attr_accessor :repository_id, :schema_id, :document_id, :is_active, :last_update, :content, :insert_date

    def attributes=(hash)
      hash.each do |key, value|
        if key=="content"
          @content = value
        else
          send("#{key}=", value)
        end
      end
    end

    def attributes
      instance_values
    end
  end

  class GetDocumentsResponse
    include ActiveModel::Serializers::JSON

    attr_accessor :count, :total_count, :limit, :offset, :documents

    def attributes=(hash)
      hash.each do |key, value|
        send("#{key}=", value)
      end
    end

    def attributes
      instance_values
    end
  end

  class Documents < ChinoBaseAPI

    def get_document(document_id)
      check_string(document_id)
      d = Document.new
      d.from_json(get_resource("/documents/#{document_id}").to_json, true)
      d
    end

    def list_documents(schema_id, full_document, limit=nil, offset=nil)
      check_string(schema_id)
      check_boolean(full_document)
      docs = GetDocumentsResponse.new
      if limit==nil && offset==nil
        if full_document
          docs.from_json(get_resource("/schemas/#{schema_id}/documents", ChinoRuby::QUERY_DEFAULT_LIMIT, 0, true).to_json)
        else
          docs.from_json(get_resource("/schemas/#{schema_id}/documents", ChinoRuby::QUERY_DEFAULT_LIMIT, 0).to_json)
        end
      else
        if full_document
          docs.from_json(get_resource("/schemas/#{schema_id}/documents", limit, offset, true).to_json)
        else
          docs.from_json(get_resource("/schemas/#{schema_id}/documents", limit, offset).to_json)
        end
      end
      ds = docs.documents
      docs.documents = []
      ds.each do |d|
        doc = Document.new
        doc.from_json(d.to_json)
        docs.documents.push(doc)
      end
      docs
    end

    def create_document(schema_id, content)
      check_string(schema_id)
      check_json(content)
      data = {"content": content}.to_json
      document = Document.new
      document.from_json(post_resource("/schemas/#{schema_id}/documents", data).to_json, true)
      document
    end

    def update_document(document_id, content, is_active=nil)
      check_string(document_id)
      check_json(content)
      if is_active.nil?
        data = {"content": content}.to_json
      else
        data = {"content": content, "is_active": is_active}.to_json
      end
      document = Document.new
      document.from_json(put_resource("/documents/#{document_id}", data).to_json, true)
      document
    end

    def delete_document(document_id, force)
      check_string(document_id)
      check_boolean(force)
      delete_resource("/documents/#{document_id}", force)
    end
  end

#------------------------------COLLECTIONS-----------------------------------#

  class Collection
    include ActiveModel::Serializers::JSON

    attr_accessor :collection_id, :name, :is_active, :last_update, :insert_date

    def attributes=(hash)
      hash.each do |key, value|
        send("#{key}=", value)
      end
    end

    def attributes
      instance_values
    end
  end

  class GetCollectionsResponse
    include ActiveModel::Serializers::JSON

    attr_accessor :count, :total_count, :limit, :offset, :collections

    def attributes=(hash)
      hash.each do |key, value|
        send("#{key}=", value)
      end
    end

    def attributes
      instance_values
    end
  end

  class Collections < ChinoBaseAPI

    def get_collection(collection_id)
      check_string(collection_id)
      col = Collection.new
      col.from_json(get_resource("/collections/#{collection_id}").to_json, true)
      col
    end

    def list_collections(limit=nil, offset=nil)
      cols = GetCollectionsResponse.new
      if limit==nil && offset==nil
        cols.from_json(get_resource("/collections", ChinoRuby::QUERY_DEFAULT_LIMIT, 0).to_json)
      else
        cols.from_json(get_resource("/collections", limit, offset).to_json)
      end
      cs = cols.collections
      cols.collections = []
      cs.each do |c|
        col = Collection.new
        col.from_json(c.to_json)
        cols.collections.push(col)
      end
      cols
    end

    def create_collection(name)
      check_string(name)
      data = {"name": name}.to_json
      col = Collection.new
      col.from_json(post_resource("/collections", data).to_json, true)
      col
    end

    def update_collection(collection_id, name)
      check_string(collection_id)
      check_string(name)
      data = {"name": name}.to_json
      col = Collection.new
      col.from_json(put_resource("/collections/#{collection_id}", data).to_json, true)
      col
    end

    def delete_collection(collection_id, force)
      check_string(collection_id)
      check_boolean(force)
      delete_resource("/collections/#{collection_id}", force)
    end

    def add_document(document_id, collection_id)
      check_string(document_id)
      check_string(collection_id)
      post_resource("/collections/#{collection_id}/documents/#{document_id}")
    end

    def remove_document(document_id, collection_id)
      check_string(document_id)
      check_string(collection_id)
      delete_resource("/collections/#{collection_id}/documents/#{document_id}", false)
    end

    def list_documents(collection_id, limit=nil, offset=nil)
      check_string(collection_id)
      docs = GetDocumentsResponse.new
      if limit==nil && offset==nil
        docs.from_json(get_resource("/collections/#{collection_id}/documents", ChinoRuby::QUERY_DEFAULT_LIMIT, 0).to_json)
      else
        docs.from_json(get_resource("/collections/#{collection_id}/documents", limit, offset).to_json)
      end
      ds = docs.documents
      docs.documents = []
      ds.each do |d|
        doc = Document.new
        doc.from_json(d.to_json)
        docs.documents.push(doc)
      end
      docs
    end
  end

#------------------------------PERMISSIONS-----------------------------------#

  class Permission
    include ActiveModel::Serializers::JSON

    attr_accessor :access, :parent_id, :resource_id, :resource_type, :permission

    def attributes=(hash)
      hash.each do |key, value|
        send("#{key}=", value)
      end
    end

    def attributes
      instance_values
    end
  end

  class GetPermissionsResponse
    include ActiveModel::Serializers::JSON

    attr_accessor :count, :total_count, :limit, :offset, :permissions

    def attributes=(hash)
      hash.each do |key, value|
        send("#{key}=", value)
      end
    end

    def attributes
      instance_values
    end
  end

  class Permissions < ChinoBaseAPI
    def list_permissions(limit=nil, offset=nil)
      perms = GetPermissionsResponse.new
      if limit==nil && offset==nil
        perms.from_json(get_resource("/perms", ChinoRuby::QUERY_DEFAULT_LIMIT, 0).to_json)
      else
        perms.from_json(get_resource("/perms", limit, offset).to_json)
      end
      ps = perms.permissions
      perms.permissions = []
      ps.each do |p|
        perm = Permission.new
        perm.from_json(p.to_json)
        perms.permissions.push(perm)
      end
      perms
    end

    def read_permissions_on_a_document(document_id, limit=nil, offset=nil)
      check_string(document_id)
      perms = GetPermissionsResponse.new
      if limit==nil && offset==nil
        perms.from_json(get_resource("/perms/documents/#{document_id}", ChinoRuby::QUERY_DEFAULT_LIMIT, 0).to_json)
      else
        perms.from_json(get_resource("/perms/documents/#{document_id}", limit, offset).to_json)
      end
      ps = perms.permissions
      perms.permissions = []
      ps.each do |p|
        perm = Permission.new
        perm.from_json(p.to_json)
        perms.permissions.push(perm)
      end
      perms
    end

    def read_permissions_of_a_user(user_id, limit=nil, offset=nil)
      check_string(user_id)
      perms = GetPermissionsResponse.new
      if limit==nil && offset==nil
        perms.from_json(get_resource("/perms/users/#{user_id}", ChinoRuby::QUERY_DEFAULT_LIMIT, 0).to_json)
      else
        perms.from_json(get_resource("/perms/users/#{user_id}", limit, offset).to_json)
      end
      ps = perms.permissions
      perms.permissions = []
      ps.each do |p|
        perm = Permission.new
        perm.from_json(p.to_json)
        perms.permissions.push(perm)
      end
      perms
    end

    def read_permissions_of_a_group(group_id, limit=nil, offset=nil)
      check_string(group_id)
      perms = GetPermissionsResponse.new
      if limit==nil && offset==nil
        perms.from_json(get_resource("/perms/groups/#{group_id}", ChinoRuby::QUERY_DEFAULT_LIMIT, 0).to_json)
      else
        perms.from_json(get_resource("/perms/groups/#{group_id}", limit, offset).to_json)
      end
      ps = perms.permissions
      perms.permissions = []
      ps.each do |p|
        perm = Permission.new
        perm.from_json(p.to_json)
        perms.permissions.push(perm)
      end
      perms
    end

    def permissions_on_resources(action, resource_type, subject_type, subject_id, manage, authorize)
      check_string(action)
      check_string(resource_type)
      check_string(subject_type)
      check_string(subject_id)
      check_json(manage)
      check_json(authorize)
      data = {"manage": manage, "authorize": authorize}.to_json
      post_resource_with_string_result("/perms/#{action}/#{resource_type}/#{subject_type}/#{subject_id}", data)
    end

    def permissions_on_a_resource(action, resource_type, resource_id, subject_type, subject_id, manage, authorize)
      check_string(action)
      check_string(resource_type)
      check_string(resource_id)
      check_string(subject_type)
      check_string(subject_id)
      check_json(manage)
      check_json(authorize)
      data = {"manage": manage, "authorize": authorize}.to_json
      post_resource_with_string_result("/perms/#{action}/#{resource_type}/#{resource_id}/#{subject_type}/#{subject_id}", data)
    end

    def permissions_on_a_resource_children(action, resource_type, resource_id, resource_children, subject_type, subject_id, manage, authorize)
      check_string(action)
      check_string(resource_type)
      check_string(resource_id)
      check_string(resource_children)
      check_string(subject_type)
      check_string(subject_id)
      check_json(manage)
      check_json(authorize)
      data = {"manage": manage, "authorize": authorize}.to_json
      post_resource_with_string_result("/perms/#{action}/#{resource_type}/#{resource_id}/#{resource_children}/#{subject_type}/#{subject_id}", data)
    end

    def permissions_on_a_resource_children_created_document(action, resource_type, resource_id, resource_children, subject_type, subject_id, manage, authorize, manage_created_document, authorize_created_document)
      check_string(action)
      check_string(resource_type)
      check_string(resource_id)
      check_string(resource_children)
      check_string(subject_type)
      check_string(subject_id)
      check_json(manage)
      check_json(authorize)
      data = {"manage": manage, "authorize": authorize, "created_document": { "manage": manage_created_document, "authorize": authorize_created_document}}.to_json
      post_resource_with_string_result("/perms/#{action}/#{resource_type}/#{resource_id}/#{resource_children}/#{subject_type}/#{subject_id}", data)
    end

  end

#------------------------------SEARCH-----------------------------------#

  class FilterOption < CheckValues
    attr_accessor :field, :type, :value

    def initialize(field, type, value)
      check_string(field)
      check_string(type)
      check_json(value)
      self.field = field
      self.type = type
      self.value = value
    end

    def to_json
      {"field": field, "type": type, "value": value}.to_json
    end
  end

  class SortOption < CheckValues
    attr_accessor :field, :order

    def initialize(field, order)
      check_string(field)
      check_string(order)
      self.field = field
      self.order = order
    end

    def to_json
      {"field": field, "order": order}.to_json
    end
  end

  class Search < ChinoBaseAPI
    def search_documents(schema_id, result_type, filter_type, sort, filter, limit=nil, offset=nil)
      check_string(schema_id)
      check_string(result_type)
      check_string(filter_type)
      check_json(sort)
      check_json(filter)
      data = {"result_type": result_type, "filter_type": filter_type, "filter": filter, "sort": sort}.to_json
      docs = GetDocumentsResponse.new
      if limit==nil && offset==nil
        docs.from_json(post_resource("/search/documents/#{schema_id}", data, ChinoRuby::QUERY_DEFAULT_LIMIT, 0).to_json)
      else
        docs.from_json(post_resource("/search/documents/#{schema_id}", data, limit, offset).to_json)
      end
      ds = docs.documents
      docs.documents = []
      ds.each do |d|
        doc = Document.new
        doc.from_json(d.to_json)
        docs.documents.push(doc)
      end
      docs
    end

    def search_users(user_schema_id, result_type, filter_type, sort, filter, limit=nil, offset=nil)
      check_string(user_schema_id)
      check_string(result_type)
      check_string(filter_type)
      check_json(sort)
      check_json(filter)
      data = {"result_type": result_type, "filter_type": filter_type, "filter": filter, "sort": sort}.to_json
      users = GetUsersResponse.new
      if limit==nil && offset==nil
        users.from_json(post_resource("/search/users/#{user_schema_id}", data, ChinoRuby::QUERY_DEFAULT_LIMIT, 0).to_json)
      else
        users.from_json(post_resource("/search/users/#{user_schema_id}", data, limit, offset).to_json)
      end
      us = users.users
      users.users = []
      us.each do |u|
        user = User.new
        user.from_json(u.to_json)
        users.users.push(user)
      end
      users
    end
  end

#------------------------------BLOBS-----------------------------------#

  class InitBlobResponse < CheckValues
    include ActiveModel::Serializers::JSON

    attr_accessor :upload_id, :expire_date, :offset

    def attributes=(hash)
      hash.each do |key, value|
        send("#{key}=", value)
      end
    end

    def attributes
      instance_values
    end
  end

  class Blob < CheckValues
    include ActiveModel::Serializers::JSON

    attr_accessor :bytes, :blob_id, :sha1, :document_id, :md5

    def attributes=(hash)
      hash.each do |key, value|
        send("#{key}=", value)
      end
    end

    def attributes
      instance_values
    end
  end

  class GetBlobResponse < CheckValues
    include ActiveModel::Serializers::JSON

    attr_accessor :blob_id, :path, :filename, :size, :sha1, :md5

    def attributes=(hash)
      hash.each do |key, value|
        send("#{key}=", value)
      end
    end

    def attributes
      instance_values
    end
  end

  class Blobs < ChinoBaseAPI

    def upload_blob(path, filename, document_id, field)
      chunk_size = 1024*32
      check_string(path)
      check_string(document_id)
      check_string(field)
      check_string(filename)
      blob = InitBlobResponse.new
      blob = init_upload(filename, document_id, field)
      bytes = []
      offset = 0
      #FIXME: this is relative to the LIBRARY directory, not running app
      file_path = File.join File.expand_path("../..", File.dirname(__FILE__)), path, filename
      File.open(file_path, 'rb') { |file|
        while (buffer = file.read(chunk_size)) do
          upload_chunk(blob.upload_id, buffer, offset)
          offset = offset+buffer.length
        end
        commit_upload(blob.upload_id)
      }
    end

    def init_upload(filename, document_id, field)
      check_string(filename)
      check_string(document_id)
      check_string(field)
      data = {"file_name": filename, "document_id": document_id, "field": field}.to_json
      blob = InitBlobResponse.new
      blob.from_json(ActiveSupport::JSON.decode(post_resource("/blobs", data).to_json)['blob'].to_json)
      blob
    end

    def upload_chunk(upload_id, bytes, offset)
      uri = return_uri("/blobs/#{upload_id}")
      req = Net::HTTP::Put.new(uri)
      req.body = bytes
      req.add_field("length", bytes.length)
      req.add_field("offset", offset)
      req.add_field("Content-Type", "application/octet-stream")
      if @customer_id == "Bearer "
        req.add_field("Authorization", @customer_id+@customer_key)
      else
        req.basic_auth @customer_id, @customer_key
      end
      res = Net::HTTP.start(uri.hostname, uri.port, :use_ssl => true) {|http|
        http.request(req)
      }
      blob = InitBlobResponse.new
      blob.from_json(parse_response(res)['data'].to_json, true)
      blob
    end

    def commit_upload(upload_id)
      check_string(upload_id)
      data = {"upload_id": upload_id}.to_json
      blob = Blob.new
      blob.from_json(post_resource("/blobs/commit", data).to_json, true)
      blob
    end

    def get(blob_id, destination)
      check_string(blob_id)
      check_string(destination)
      uri = return_uri("/blobs/#{blob_id}")
      req = Net::HTTP::Get.new(uri.path)
      if @customer_id == "Bearer "
        req.add_field("Authorization", @customer_id+@customer_key)
      else
        req.basic_auth @customer_id, @customer_key
      end
      res = Net::HTTP.start(uri.hostname, uri.port, :use_ssl => true) {|http|
        http.request(req)
      }
      blob = GetBlobResponse.new
      blob.blob_id = blob_id
      filename = res.header['Content-Disposition'].partition('=').last
      blob.filename = filename
      blob.path = destination
      #FIXME: this is relative to the LIBRARY directory, not running app
      file_path = File.join File.expand_path("../..", File.dirname(__FILE__)), destination
      FileUtils.mkdir_p(file_path) unless File.exist?(file_path)
      File.open(File.join(file_path+filename), 'wb') { |file|
        file << res.body
        blob.md5 = (Digest::MD5.file file).hexdigest
        blob.sha1 = (Digest::SHA1.file file).hexdigest
        blob.size = file.size
      }
      blob
    end

    def delete_blob(blob_id, force)
      check_string(blob_id)
      check_boolean(force)
      delete_resource("/blobs/#{blob_id}", force)
    end
  end

end
