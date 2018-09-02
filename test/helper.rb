# encoding: UTF-8
# frozen_string_literal: true

Bundler.require

Test::Unit::TestCase.test_order = :random

require "active_support/inflections"
require "active_support/core_ext/kernel/reporting"
require "securerandom"
require "openssl"
require "base64"
require "set"

ActiveSupport::Inflector.inflections do |inflect|
  inflect.acronym "API"
  inflect.acronym "v1"
  inflect.acronym "v2"
end

module MyAPIv1
  class JWTAuthenticator < JWT::Authenticator

  end
end

ENV["MY_API_V2_JWT_ISS"] = "foo"
ENV["MY_API_V2_JWT_AUD"] = "foo,bar,baz"
ENV["MY_API_V2_JWT_SUB"] = "session"
ENV["MY_API_V2_JWT_ALG"] = "RS256"
ENV["MY_API_V2_JWT_KEY"] = Base64.urlsafe_encode64(OpenSSL::PKey::RSA.generate(2048).to_pem)

module MyAPIv2
  class JWTAuthenticator < JWT::Authenticator

  private

    def public_key(*)
      OpenSSL::PKey.read(Base64.urlsafe_decode64(ENV["MY_API_V2_JWT_KEY"])).public_key
    end
  end
end
