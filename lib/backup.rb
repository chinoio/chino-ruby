class ChinoClient
    
    # Args:
    # * +oauth2_access_token+: Obtained via DropboxOAuth2Flow or DropboxOAuth2FlowNoRedirect.
    # * +locale+: The user's current locale (used to localize error messages).
    def initialize(oauth2_access_token, root="auto", locale=nil)
        if oauth2_access_token.is_a?(String)
            @session = DropboxOAuth2Session.new(oauth2_access_token, locale)
            elsif oauth2_access_token.is_a?(DropboxSession)
            @session = oauth2_access_token
            @session.get_access_token
            if not locale.nil?
                @session.locale = locale
            end
            else
            raise ArgumentError.new("oauth2_access_token doesn't have a valid type")
        end
        
        @root = root.to_s  # If they passed in a symbol, make it a string
        
        if not ["dropbox","app_folder","auto"].include?(@root)
            raise ArgumentError.new("root must be :dropbox, :app_folder, or :auto")
        end
        if @root == "app_folder"
            #App Folder is the name of the access type, but for historical reasons
            #sandbox is the URL root component that indicates this
            @root = "sandbox"
        end
    end
    
    # Returns some information about the current user's Dropbox account (the "current user"
    # is the user associated with the access token you're using).
    #
    # For a detailed description of what this call returns, visit:
    # https://www.dropbox.com/developers/reference/api#account-info
    def account_info()
        response = @session.do_get "/account/info"
        Dropbox::parse_response(response)
    end
    
    # Disables the access token that this +DropboxClient+ is using.  If this call
    # succeeds, further API calls using this object will fail.
    def disable_access_token
        @session.do_post "/disable_access_token"
        nil
    end
    
    # If this +DropboxClient+ was created with an OAuth 1 access token, this method
    # can be used to create an equivalent OAuth 2 access token.  This can be used to
    # upgrade your app's existing access tokens from OAuth 1 to OAuth 2.
    def create_oauth2_access_token
        if not @session.is_a?(DropboxSession)
            raise ArgumentError.new("This call requires a DropboxClient that is configured with " \
                                    "an OAuth 1 access token.")
        end
        response = @session.do_post "/oauth2/token_from_oauth1"
        Dropbox::parse_response(response)['access_token']
    end
end

class ChinoBaseAPI # :nodoc:
    
    attr_writer :locale
    
    def initialize(locale)
        @locale = locale
    end
    
    private
    
    def build_url(path, server)
        host = Chino::API_SERVER
        full_path = "/#{path}"
        return URI::HTTPS.build({:host => host, :path => full_path})
    end
    
    def build_url_with_params(path, params, server) # :nodoc:
        target = build_url(path, server)
        target.query = Dropbox::make_query_string(params)
        return target
    end
    
    protected
    
    def do_http(uri, request) # :nodoc:
        sign_request(request)
        Dropbox::do_http(uri, request)
    end
    
    public
    
    def do_get(path, params=nil, server=:api)  # :nodoc:
        params ||= {}
        assert_authorized
        uri = build_url_with_params(path, params, server)
        do_http(uri, Net::HTTP::Get.new(uri.request_uri))
    end
    
    def do_http_with_body(uri, request, body)
        if body != nil
            if body.is_a?(Hash)
                request.set_form_data(Dropbox::clean_params(body))
                elsif body.respond_to?(:read)
                if body.respond_to?(:length)
                    request["Content-Length"] = body.length.to_s
                    elsif body.respond_to?(:stat) && body.stat.respond_to?(:size)
                    request["Content-Length"] = body.stat.size.to_s
                    else
                    raise ArgumentError, "Don't know how to handle 'body' (responds to 'read' but not to 'length' or 'stat.size')."
                end
                request.body_stream = body
                else
                s = body.to_s
                request["Content-Length"] = s.length
                request.body = s
            end
        end
        do_http(uri, request)
    end
    
    def do_post(path, params=nil, headers=nil, server=:api)  # :nodoc:
        params ||= {}
        assert_authorized
        uri = build_url(path, server)
        params['locale'] = @locale
        do_http_with_body(uri, Net::HTTP::Post.new(uri.request_uri, headers), params)
    end
    
    def do_put(path, params=nil, headers=nil, body=nil, server=:api)  # :nodoc:
        params ||= {}
        assert_authorized
        uri = build_url_with_params(path, params, server)
        do_http_with_body(uri, Net::HTTP::Put.new(uri.request_uri, headers), body)
    end
end

# DropboxSession is responsible for holding OAuth 1 information.  It knows how to take your consumer key and secret
# and request an access token, an authorize url, and get an access token.  You just need to pass it to
# DropboxClient after its been authorized.
class DropboxSession < DropboxSessionBase  # :nodoc:
    
    # * consumer_key - Your Dropbox application's "app key".
    # * consumer_secret - Your Dropbox application's "app secret".
    def initialize(consumer_key, consumer_secret, locale=nil)
        super(locale)
        @consumer_key = consumer_key
        @consumer_secret = consumer_secret
        @request_token = nil
        @access_token = nil
    end
    
    private
    
    def build_auth_header(token) # :nodoc:
        header = "OAuth oauth_version=\"1.0\", oauth_signature_method=\"PLAINTEXT\", " +
        "oauth_consumer_key=\"#{URI.escape(@consumer_key)}\", "
        if token
            key = URI.escape(token.key)
            secret = URI.escape(token.secret)
            header += "oauth_token=\"#{key}\", oauth_signature=\"#{URI.escape(@consumer_secret)}&#{secret}\""
            else
            header += "oauth_signature=\"#{URI.escape(@consumer_secret)}&\""
        end
        header
    end
    
    def do_get_with_token(url, token) # :nodoc:
        uri = URI.parse(url)
        request = Net::HTTP::Get.new(uri.request_uri)
        request.add_field('Authorization', build_auth_header(token))
        Dropbox::do_http(uri, request)
    end
    
    protected
    
    def sign_request(request)  # :nodoc:
        request.add_field('Authorization', build_auth_header(@access_token))
    end
    
    public
    
    def get_token(url_end, input_token, error_message_prefix) #: nodoc:
        response = do_get_with_token("https://#{Dropbox::API_SERVER}:443/#{Dropbox::API_VERSION}/oauth#{url_end}", input_token)
        if not response.kind_of?(Net::HTTPSuccess) # it must be a 200
            raise DropboxAuthError.new("#{error_message_prefix}  Server returned #{response.code}: #{response.message}.", response)
        end
        parts = CGI.parse(response.body)
        
        if !parts.has_key? "oauth_token" and parts["oauth_token"].length != 1
            raise DropboxAuthError.new("Invalid response from #{url_end}: missing \"oauth_token\" parameter: #{response.body}", response)
        end
        if !parts.has_key? "oauth_token_secret" and parts["oauth_token_secret"].length != 1
            raise DropboxAuthError.new("Invalid response from #{url_end}: missing \"oauth_token\" parameter: #{response.body}", response)
        end
        
        OAuthToken.new(parts["oauth_token"][0], parts["oauth_token_secret"][0])
    end
    
    # This returns a request token.  Requests one from the dropbox server using the provided application key and secret if nessecary.
    def get_request_token()
        @request_token ||= get_token("/request_token", nil, "Error getting request token.  Is your app key and secret correctly set?")
    end
    
    # This returns a URL that your user must visit to grant
    # permissions to this application.
    def get_authorize_url(callback=nil)
        get_request_token()
        
        url = "/#{Dropbox::API_VERSION}/oauth/authorize?oauth_token=#{URI.escape(@request_token.key)}"
        if callback
            url += "&oauth_callback=#{URI.escape(callback)}"
        end
        if @locale
            url += "&locale=#{URI.escape(@locale)}"
        end
        
        "https://#{Dropbox::WEB_SERVER}#{url}"
    end
    
    # Clears the access_token
    def clear_access_token
        @access_token = nil
    end
    
    # Returns the request token, or nil if one hasn't been acquired yet.
    def request_token
        @request_token
    end
    
    # Returns the access token, or nil if one hasn't been acquired yet.
    def access_token
        @access_token
    end
    
    # Given a saved request token and secret, set this location's token and secret
    # * token - this is the request token
    # * secret - this is the request token secret
    def set_request_token(key, secret)
        @request_token = OAuthToken.new(key, secret)
    end
    
    # Given a saved access token and secret, you set this Session to use that token and secret
    # * token - this is the access token
    # * secret - this is the access token secret
    def set_access_token(key, secret)
        @access_token = OAuthToken.new(key, secret)
    end
    
    # Returns the access token. If this DropboxSession doesn't yet have an access_token, it requests one
    # using the request_token generate from your app's token and secret.  This request will fail unless
    # your user has gone to the authorize_url and approved your request
    def get_access_token
        return @access_token if authorized?
        
        if @request_token.nil?
            raise RuntimeError.new("No request token. You must set this or get an authorize url first.")
        end
        
        @access_token = get_token("/access_token", @request_token,  "Couldn't get access token.")
    end
    
    # If we have an access token, then do nothing.  If not, throw a RuntimeError.
    def assert_authorized
        unless authorized?
            raise RuntimeError.new('Session does not yet have a request token')
        end
    end
    
    # Returns true if this Session has been authorized and has an access_token.
    def authorized?
        !!@access_token
    end
    
    # serialize the DropboxSession.
    # At DropboxSession's state is capture in three key/secret pairs.  Consumer, request, and access.
    # Serialize returns these in a YAML string, generated from a converted array of the form:
    # [consumer_key, consumer_secret, request_token.token, request_token.secret, access_token.token, access_token.secret]
    # access_token is only included if it already exists in the DropboxSesssion
    def serialize
        toreturn = []
        if @access_token
            toreturn.push @access_token.secret, @access_token.key
        end
        
        get_request_token
        
        toreturn.push @request_token.secret, @request_token.key
        toreturn.push @consumer_secret, @consumer_key
        
        toreturn.to_yaml
    end
    
    # Takes a serialized DropboxSession YAML String and returns a new DropboxSession object
    def self.deserialize(ser)
    ser = YAML::load(ser)
    session = DropboxSession.new(ser.pop, ser.pop)
    session.set_request_token(ser.pop, ser.pop)
    
    if ser.length > 0
    session.set_access_token(ser.pop, ser.pop)
end
session
end
end
