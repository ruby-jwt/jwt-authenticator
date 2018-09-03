# encoding: UTF-8
# frozen_string_literal: true

require_relative "helper"

class JWTAuthenticatorTest < Test::Unit::TestCase
  test "gem version" do
    assert defined?(JWT::Authenticator::VERSION)
  end

  test "singleton" do
    assert_equal 1, ([JWT::Authenticator] * 3).map(&:instance).map(&:object_id).uniq.count
  end

  test "loading token verification options from environment" do
    default = {
      verify_aud: false,
      verify_expiration: true,
      verify_iat: true,
      verify_iss: false,
      verify_jti: true,
      verify_not_before: true,
      verify_sub: false }

    assert_equal(default, my_api_v1_token_verification_options)

    modify_environment "MY_API_V1_JWT_VERIFY_EXP", "false" do
      assert_equal(default.merge(verify_expiration: false), my_api_v1_token_verification_options)
    end

    modify_environment "MY_API_V1_JWT_VERIFY_NBF", "false" do
      assert_equal(default.merge(verify_not_before: false), my_api_v1_token_verification_options)
    end

    modify_environment "MY_API_V1_JWT_ISS", " foo " do
      assert_equal(default.merge(iss: "foo", verify_iss: true), my_api_v1_token_verification_options)
    end

    modify_environment "MY_API_V1_JWT_VERIFY_IAT", "false" do
      assert_equal(default.merge(verify_iat: false), my_api_v1_token_verification_options)
    end

    modify_environment "MY_API_V1_JWT_VERIFY_JTI", "false" do
      assert_equal(default.merge(verify_jti: false), my_api_v1_token_verification_options)
    end

    modify_environment "MY_API_V1_JWT_AUD", "foo, bar, baz" do
      assert_equal(default.merge(aud: %w[foo bar baz], verify_aud: true), my_api_v1_token_verification_options)
    end

    modify_environment "MY_API_V1_JWT_SUB", " session " do
      assert_equal(default.merge(sub: "session", verify_sub: true), my_api_v1_token_verification_options)
    end

    modify_environment "MY_API_V1_JWT_ALG", " RS256" do
      assert_equal(default.merge(algorithms: %w[RS256]), my_api_v1_token_verification_options)
    end

    modify_environment "MY_API_V1_JWT_LEEWAY", "30" do
      assert_equal(default.merge(leeway: 30), my_api_v1_token_verification_options)
    end

    modify_environment "MY_API_V1_JWT_IAT_LEEWAY", "30" do
      assert_equal(default.merge(iat_leeway: 30), my_api_v1_token_verification_options)
    end

    modify_environment "MY_API_V1_JWT_EXP_LEEWAY", "30" do
      assert_equal(default.merge(exp_leeway: 30), my_api_v1_token_verification_options)
    end

    modify_environment "MY_API_V1_JWT_NBF_LEEWAY", "30" do
      assert_equal(default.merge(nbf_leeway: 30), my_api_v1_token_verification_options)
    end
  end

  test "blank token" do
    error = assert_raises(JWT::Authenticator::Error) { JWT::Authenticator.instance.call(" ") }
    assert_match(/\bmissing\b/i, error.message)
    assert_equal(101, error.code)
  end

  test "token with invalid type" do
    error = assert_raises(JWT::Authenticator::Error) { JWT::Authenticator.instance.call("Beer XXX.YYY.ZZZ") }
    assert_match(/\binvalid\b/i, error.message)
    assert_equal(102, error.code)
  end

  test "token decoding and verification" do
    jwt = my_api_v2_jwt_encode(my_api_v2_jwt_payload)
    payload, header = my_api_v2_jwt_decode(jwt)
    assert %i[jti iss aud sub dat].to_set == payload.keys.to_set
    assert %i[alg].to_set == header.keys.to_set
  end

  test "wrong iss" do
    jwt = my_api_v2_jwt_encode(my_api_v2_jwt_payload.merge(iss: "qux"))
    error = assert_raises(JWT::Authenticator::Error) { my_api_v2_jwt_decode(jwt) }
    assert_match(/\binvalid issuer\b/i, error.message)
    assert_equal(103, error.code)
  end

  test "missing iss" do
    jwt = my_api_v2_jwt_encode(my_api_v2_jwt_payload.tap { |p| p.delete(:iss) })
    error = assert_raises(JWT::Authenticator::Error) { my_api_v2_jwt_decode(jwt) }
    assert_match(/\binvalid issuer\b/i, error.message)
    assert_equal(103, error.code)
  end

  test "missing aud" do
    jwt = my_api_v2_jwt_encode(my_api_v2_jwt_payload.tap { |p| p.delete(:aud) })
    error = assert_raises(JWT::Authenticator::Error) { my_api_v2_jwt_decode(jwt) }
    assert_match(/\binvalid audience\b/i, error.message)
    assert_equal(103, error.code)
  end

  test "wrong aud" do
    jwt = my_api_v2_jwt_encode(my_api_v2_jwt_payload.merge(aud: "qux"))
    error = assert_raises(JWT::Authenticator::Error) { my_api_v2_jwt_decode(jwt) }
    assert_match(/\binvalid audience\b/i, error.message)
    assert_equal(103, error.code)
  end

  test "missing sub" do
    jwt = my_api_v2_jwt_encode(my_api_v2_jwt_payload.tap { |p| p.delete(:sub) })
    error = assert_raises(JWT::Authenticator::Error) { my_api_v2_jwt_decode(jwt) }
    assert_match(/\binvalid subject\b/i, error.message)
    assert_equal(103, error.code)
  end

  test "wrong sub" do
    jwt = my_api_v2_jwt_encode(my_api_v2_jwt_payload.merge(sub: "qux"))
    error = assert_raises(JWT::Authenticator::Error) { my_api_v2_jwt_decode(jwt) }
    assert_match(/\binvalid subject\b/i, error.message)
    assert_equal(103, error.code)
  end

  test "token is expired" do
    jwt = my_api_v2_jwt_encode(my_api_v2_jwt_payload.merge(exp: Time.now.to_i - 5))
    error = assert_raises(JWT::Authenticator::Error) { my_api_v2_jwt_decode(jwt) }
    assert_match(/\bexpired\b/i, error.message)
    assert_equal(103, error.code)
  end

  test "missing jti" do
    jwt = my_api_v2_jwt_encode(my_api_v2_jwt_payload.tap { |p| p.delete(:jti) })
    error = assert_raises(JWT::Authenticator::Error) { my_api_v2_jwt_decode(jwt) }
    assert_match(/\bmissing jti\b/i, error.message)
    assert_equal(103, error.code)
  end

  test "issued at in future" do
    jwt = my_api_v2_jwt_encode(my_api_v2_jwt_payload.merge(iat: Time.now.to_i + 30))
    error = assert_raises(JWT::Authenticator::Error) { my_api_v2_jwt_decode(jwt) }
    assert_match(/\binvalid iat\b/i, error.message)
    assert_equal(103, error.code)
  end

  test "loading token verification options from environment (authenticator nested under multiple modules)" do
    ENV["MY_API_V3_JWT_ISS"] = "bar"
    authenticator = MyAPI::V3::JWTAuthenticator.instance
    assert_equal(ENV["MY_API_V3_JWT_ISS"], authenticator.instance_variable_get(:@verification_options)[:iss])
  end

private

  def my_api_v1_token_verification_options
    silence_warnings { Singleton.__init__(MyAPIv1::JWTAuthenticator) }
    MyAPIv1::JWTAuthenticator.instance.instance_variable_get(:@verification_options)
  end

  def modify_environment(var, val)
    prev = ENV[var]
    ENV[var] = val
    yield
  ensure
    ENV[var] = prev
  end

  def my_api_v2_jwt_payload
    { iss: "foo", jti: SecureRandom.uuid, aud: %w[bar baz], sub: "session", dat: {} }
  end

  def my_api_v2_jwt_encode(payload)
    JWT.encode(payload, OpenSSL::PKey.read(Base64.urlsafe_decode64(ENV["MY_API_V2_JWT_KEY"])), "RS256")
  end

  def my_api_v2_jwt_decode(jwt)
    MyAPIv2::JWTAuthenticator.call("Bearer " + jwt)
  end
end
