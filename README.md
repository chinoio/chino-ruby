# ChinoRuby

Official Ruby wrapper of the Chino.io

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
@client = ChinoAPI.new(<your-customer-id>, <your-customer-key>, <server-url>)
```
The server-url parameter must be `https://api.test.chino.io/v1` or `https://api.chino.io/v1`.

## Development

After checking out the repo, run `bin/setup` to install dependencies. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## License

The gem is available as open source under the terms of the [MIT License](http://opensource.org/licenses/MIT).
