require "base64"
require "uri"
require "net/https"
require "active_model"
require "json"

module Chino
    API_TEST_SERVER = "https://api.test.chino.io/v1"
    API_SERVER = "https://api.chino.io/v1"
    QUERY_DEFAULT_LIMIT = 100
end

class ChinoAPI
    
    attr_accessor :applications, :auth
    
    def initialize(customer_id, customer_key, host_url)
        check_string(customer_id)
        check_string(customer_key)
        check_string(host_url)
        @customer_id = customer_id
        @customer_key = customer_key
        @host_url = host_url
        @applications = Applications.new(@customer_id, @customer_key)
        @auth = Auth.new(@customer_id, @customer_key)
    end
    
    def check_string(value)
        if not value.is_a?(String)
            raise ArgumentError, "{#value} must be a String, got #{value.inspect}"
        end
    end
    
    def initUser()
        
    end
end

class CheckValues
    def check_string(value)
        if not value.is_a?(String)
            raise ArgumentError, "{#value} must be a String, got #{value.inspect}"
        end
    end
    
    def check_int(value)
        if not value.is_a?(Integer)
            raise ArgumentError, "{#value} must be a Int, got #{value.inspect}"
        end
    end
    
    def check_boolean(value)
        if not !!value == value
            raise ArgumentError, "{#value} must be a Boolean, got #{value.inspect}"
        end
    end
end

class ChinoBaseAPI < CheckValues

    def initialize(customer_id, customer_key)
        if customer_id == ""
            @customer_id = "Bearer "
        end
        @customer_id = customer_id
        @customer_key = customer_key
    end

    def return_uri_with_params(path, limit, offset)
        uri = URI(Chino::API_TEST_SERVER+path+"?limit=#{limit}&offset=#{offset}")
        uri
    end
    
    def return_uri(path)
        uri = URI(Chino::API_TEST_SERVER+path)
        params = { :"Content-Type" => "application/json"}
        uri.query = URI.encode_www_form(params)
        uri
    end
    
    def get_resource(path)
        check_string(path)
        uri = return_uri(path)
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
    
    def get_resource_with_params(path, limit, offset)
        check_string(path)
        uri = return_uri_with_params(path, limit, offset)
        req = Net::HTTP::Get.new(uri)
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
    
    def post_resource(path, data)
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
        parse_response(res)['data']
    end
    
    def put_resource(path, data)
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
    
    def delete_resource(path, force)
        check_string(path)
        check_boolean(force)
        if force
            uri = return_uri(path+"?force=true")
        else
            uri = return_uri(path)
        end
        req = Net::HTTP::Delete.new(uri.path)
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

#------------------------------CHINO ERRORS-----------------------------------#

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

class ChinoAuthError < ChinoError
end

class ChinoErrorModel
    include ActiveModel::Serializers::JSON
    
    attr_accessor :message, :data, :result, :result_code
    
    def attributes=(hash)
        hash.each do |key, value|
            send("#{key}=", value)
        end
    end
    
    def attributes
        instance_values
    end
end

#------------------------------APPLICATIONS-----------------------------------#

class Application
    include ActiveModel::Serializers::JSON
    
    attr_accessor :app_name, :app_id, :app_secret, :grant_type, :redirect_url
    
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
    
    def list_applications()
        apps = GetApplicationsResponse.new
        apps.from_json(get_resource_with_params("/auth/applications", Chino::QUERY_DEFAULT_LIMIT, 0).to_json)
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
    
    def list_applications_with_params(limit, offset)
        check_int(limit)
        check_int(offset)
        apps = GetApplicationsResponse.new
        apps.from_json(get_resource_with_params("/auth/applications", limit, offset).to_json)
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
    
    def loginWithPassword(username, password, application_id, application_secret)
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
    
    def loginWithAuthenticationCode(code, redirect_url, application_id, application_secret)
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
   
   def refreshToken(refresh_token, application_id, application_secret)
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

#------------------------------USER SCHEMAS-----------------------------------#

class UserSchema
    include ActiveModel::Serializers::JSON
    
    attr_accessor :user_schema_id, :description, :is_active, :last_update, :groups, :structure, :insert_date
    
    def attributes=(hash)
        hash.each do |key, value|
            send("#{key}=", value)
        end
    end
    
    def attributes
        instance_values
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

class Field < CheckValues
    attr_accessor :type, :name, :indexed
    
    def initialize(type, name, indexed)
        check_string(type)
        check_string(name)
        check_boolean(indexed)
        self.type = type
        self.name = name
        self.indexed = indexed
    end
end

class UserSchemas < ChinoBaseAPI
    
    def get_user_schema(user_schema_id)
        check_string(user_schema_id)
        us = UserSchema.new
        us.from_json(get_resource("/user_schemas/#{user_schema_id}").to_json, true)
        us
    end
    
    def list_applications()
        apps = GetApplicationsResponse.new
        apps.from_json(get_resource_with_params("/auth/applications", Chino::QUERY_DEFAULT_LIMIT, 0).to_json)
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
    
    def list_applications_with_params(limit, offset)
        check_int(limit)
        check_int(offset)
        apps = GetApplicationsResponse.new
        apps.from_json(get_resource_with_params("/auth/applications", limit, offset).to_json)
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
    
    def create_user_schema(description, fields)
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

#------------------------------RUNNING CODE-----------------------------------#

if __FILE__ == $0
    client_token = "z4EEfL45DUHmtq1AZ1F7h73AKJejX2"
    url = "https://api.test.chino.io/v1"
    customer_id = "<your-customer-id>"
    customer_key = "<your-customer-key>"
    chinoAPI = ChinoAPI.new(customer_id, customer_key, url)
    app = chinoAPI.applications.create_application("test_creation_ruby", "password", "")
    puts app.app_name + " " + app.app_id
    app = chinoAPI.applications.get_application(app.app_id)
    puts app.app_name + " " + app.app_id
    app = chinoAPI.applications.update_application(app.app_id, "test_creation_ruby_updated", "password", "")
    puts app.app_name + " " + app.app_id
    
    usr = chinoAPI.auth.loginWithPassword("testUsernames", "testPassword", app.app_id, app.app_secret)
    puts usr.access_token + " " + usr.token_type
    
    usr = chinoAPI.auth.refreshToken(usr.refresh_token, app.app_id, app.app_secret)
    puts usr.access_token + " " + usr.token_type
    
    chinoAPI = ChinoAPI.new("Bearer ", usr.access_token, url)
    
    #chinoAPI.applications.create_application("test_creation_ruby", "password", "")
    
    puts chinoAPI.auth.logout(usr.access_token, app.app_id, app.app_secret)
    
    chinoAPI = ChinoAPI.new(customer_id, customer_key, url)
    
    apps = chinoAPI.applications.list_applications()
    puts "count: #{apps.count}"
    apps.applications.each do |a|
        puts a.app_name + " " + a.app_id
    end
    puts "offset 2, limit 2"
    apps = chinoAPI.applications.list_applications_with_params(2, 2)
    apps.applications.each do |a|
        puts a.app_name + " " + a.app_id
    end
    puts chinoAPI.applications.delete_application(app.app_id, true)
    
    fields = []
    fields.push(Field.new("string", "name", true))
end
