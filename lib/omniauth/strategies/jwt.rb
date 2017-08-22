require 'omniauth'
require 'jwt'

module OmniAuth
  module Strategies
    class JWT
      class ClaimInvalid < StandardError; end

      include OmniAuth::Strategy

      args [:secret]

      option :secret, nil
      option :algorithm, 'HS256'
      option :uid_claim, 'id'
      option :required_claims, %w(name email)
      option :auth_url, nil
      option :valid_within, nil

      def request_phase
        redirect options.auth_url
      end

      def decoded
        @decoded ||= ::JWT.decode(request.params['jwt'], options.secret, options.algorithm).reduce(&:merge)
        (options.required_claims || []).each do |field|
          raise ClaimInvalid.new("Missing required '#{field}' claim.") if !@decoded['sub'].key?(field.to_s)
        end
        raise ClaimInvalid.new("Missing required 'iat' claim.") if options.valid_within && !@decoded["iat"]
        raise ClaimInvalid.new("'iat' timestamp claim is too skewed from present.") if options.valid_within && (Time.now.to_i - @decoded["iat"]).abs > options.valid_within
        @decoded
      end

      def callback_phase
        super
      rescue ClaimInvalid => e
        fail! :claim_invalid, e
      end

      uid { decoded['sub'][options.uid_claim] }

      extra do
        {:raw_info => decoded}
      end

      info { decoded['sub'] }
    end

    class Jwt < JWT; end
  end
end