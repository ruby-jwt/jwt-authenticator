# encoding: UTF-8
# frozen_string_literal: true

require "jwt"
require "method-not-implemented"
require "active_support/core_ext/string/inflections"
require "active_support/core_ext/object/blank"
require "active_support/core_ext/string/filters"
require "active_support/core_ext/hash/keys"
require "jwt-authenticator/version"

class JWT::Authenticator
  include Singleton

  def initialize
    @verification_options = token_verification_options_from_environment \
      self.class.name.split("::")[0...-1].join("_").underscore.upcase.gsub(/_?JWT\z/, "") + "_JWT"
  end

  def call(token)
    error! type: :token_missing unless token.present?

    returned = JWT.decode token, nil, true, @verification_options do |header|
      public_key(header.deep_symbolize_keys)
    end

    returned.map(&:deep_symbolize_keys)

  rescue JWT::ExpiredSignature => e
    error! message: e.inspect, type: :token_expired

  rescue JWT::DecodeError => e
    error! message: e.inspect, type: :token_invalid
  end

protected

  def public_key(header)
    method_not_implemented
  end

  def token_verification_options_from_environment(namespace)
    namespace = namespace.gsub(/_+\z/, "")
    options = {
      verify_expiration: ENV["#{namespace}_VERIFY_EXP"] != "false",
      verify_not_before: ENV["#{namespace}_VERIFY_NBF"] != "false",
      iss:               ENV["#{namespace}_ISS"].to_s.split(",").map(&:squish).reject(&:blank?).presence, # Comma-separated values.
      verify_iat:        ENV["#{namespace}_VERIFY_IAT"] != "false",
      verify_jti:        ENV["#{namespace}_VERIFY_JTI"] != "false",
      aud:               ENV["#{namespace}_AUD"].to_s.split(",").map(&:squish).reject(&:blank?).presence, # Comma-separated values.
      sub:               ENV["#{namespace}_SUB"].to_s.squish.presence,
      algorithms:        ENV["#{namespace}_ALG"].to_s.split(",").map(&:squish).reject(&:blank?).presence, # Comma-separated values.
      leeway:            ENV["#{namespace}_LEEWAY"].to_s.squish.yield_self { |n| n.to_i if n.present? },
      iat_leeway:        ENV["#{namespace}_IAT_LEEWAY"].to_s.squish.yield_self { |n| n.to_i if n.present? },
      exp_leeway:        ENV["#{namespace}_EXP_LEEWAY"].to_s.squish.yield_self { |n| n.to_i if n.present? },
      nbf_leeway:        ENV["#{namespace}_NBF_LEEWAY"].to_s.squish.yield_self { |n| n.to_i if n.present? }
    }
    options.merge! \
      verify_sub: options[:sub].present?,
      verify_iss: options[:iss].present?,
      verify_aud: options[:aud].present?
    options.compact
  end

  def error!(**options)
    raise Error.new(**options)
  end

  class << self
    def call(token)
      instance.call(token)
    end
  end

  class Error < StandardError
    attr_reader :type

    def initialize(message: nil, type:)
      super message.presence || type.to_s.humanize
      @type = type
    end
  end
end
