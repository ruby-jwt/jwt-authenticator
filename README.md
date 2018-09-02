# JSON Web Token authentication Ruby service

The gem provides easy & extendable way to perform JSON Web Token authentication.

## Usage

Please, see the code sample below.

```ruby
module MyAPI
  #
  # Define JWT verification options using variables below:
  # 
  #   MY_API_JWT_VERIFY_EXP
  #   MY_API_JWT_VERIFY_NBF
  #   MY_API_JWT_ISS
  #   MY_API_JWT_VERIFY_IAT
  #   MY_API_JWT_VERIFY_JTI
  #   MY_API_JWT_AUD (could be comma-separated)
  #   MY_API_JWT_SUB
  #   MY_API_JWT_ALG (could be comma-separated)
  #   MY_API_JWT_LEEWAY
  #   MY_API_JWT_IAT_LEEWAY
  #   MY_API_JWT_EXP_LEEWAY
  #   MY_API_JWT_NBF_LEEWAY
  # 
  class JWTAuthenticator < JWT::Authenticator
    def call(*)
      payload, = super
      # You may want to do some additional checks here like verifying JTI is not revoked.
      # You also can return any value you want. For example, here we can return user.
      User.new(payload.slice(:uid, :email, :level)) 
    end

  protected
  
    def public_key(header)
      # You have to determine what key should be user for signature verification (based on «header») and return public key.
      # The returned value must be instance of OpenSSL::PKey::RSA.
    end
  end
end
```
