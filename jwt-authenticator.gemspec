# encoding: UTF-8
# frozen_string_literal: true

require File.expand_path("../lib/jwt-authenticator/version", __FILE__)

Gem::Specification.new do |s|
  s.name                  = "jwt-authenticator"
  s.version               = JWT::Authenticator::VERSION
  s.author                = "Yaroslav Konoplov"
  s.email                 = "eahome00@gmail.com"
  s.summary               = "JSON Web Token authentication Ruby service."
  s.description           = "The gem provides easy & extendable way to perform JSON Web Token authentication."
  s.homepage              = "https://github.com/ruby-jwt/jwt-authenticator"
  s.license               = "Apache-2.0"
  s.files                 = `git ls-files -z`.split("\x0")
  s.test_files            = `git ls-files -z -- {test,spec,features}/*`.split("\x0")
  s.require_paths         = ["lib"]
  s.required_ruby_version = "~> 2.5"

  s.add_dependency             "jwt", "~> 2.1"
  s.add_dependency             "method-not-implemented", "~> 1.0"
  s.add_dependency             "activesupport", ">= 4.0", "< 6.0"
  s.add_development_dependency "bundler", "~> 1.7"
end
