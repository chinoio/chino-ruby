# ChinoRuby

Official Ruby wrapper of the Chino.io API

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'chino_ruby'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install chino_ruby

## Usage

Initialize a Chino.io client variable as follow

```ruby
@client = ChinoAPI.new("<your-customer-id>", "<your-customer-key>", "<server-url>")
```
The server-url parameter must be `https://api.test.chino.io/v1` or `https://api.chino.io/v1`.
Once you created your client variable, you can use it to call functions and communicate with the server.  
The creation of a basic document is as follow:  
- First, create the Repository  
```ruby
@repo = @client.repositories.create_repository("test repo description")
```
- Then create the Schema  
```ruby
fields = []
fields.push(Field.new("string", "test_string", true))
fields.push(Field.new("integer", "test_integer", true))

@schema = @client.schemas.create_schema(@repo.repository_id, "test schema description", fields)
```
- Finally, create the Document  
```ruby
content = Hash.new
content["test_string"] = "sample value ruby"
content["test_integer"] = 123

@doc = @client.documents.create_document(@schema.schema_id, content)
```
## Running the Tests
You have to run the following commands in the terminal in order to run the tests:
```
$ gem install bundler
```
```
$ bundle install
```
```
$ cd test
```
```
$ bundle exec ruby sdk_test.rb
```
## Development

After checking out the repo, run `bin/setup` to install dependencies. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
