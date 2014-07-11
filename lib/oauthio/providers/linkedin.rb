module Oauthio
  module Providers
    class Linkedin
      include Base

      def initialize(access_token, secret, options)
        @access_token = access_token
        @secret = secret
        @options = options
      end

      def uid
        raw_info['id']
      end

      def info
        {
          :name => user_name,
          :email => raw_info['emailAddress'],
          :nickname => user_name,
          :first_name => raw_info['firstName'],
          :last_name => raw_info['lastName'],
          :location => raw_info['location'],
          :description => raw_info['headline'],
          :image => raw_info['pictureUrl'],
          :urls => {
            'public_profile' => raw_info['publicProfileUrl']
          }
        }
      end

      def extra
        {'raw_info' => raw_info}
      end

      def access_token
        client = ::OAuth2::Client.new(@options.client_id, @options.client_secret,
                                      {
                                        site: 'https://api.linkedin.com',
                                        authorize_url: 'https://www.linkedin.com/uas/oauth2/authorization?response_type=code',
                                        token_url: 'https://www.linkedin.com/uas/oauth2/accessToken',
                                      })
        # @access_token.token is blank until oauth.io will support OAuth 2 for Linkedin
        ::OAuth2::AccessToken.new(client, @access_token.token, {
          mode: :query,
          param_name: 'oauth2_access_token',
          expires_in: @access_token.expires_in,
          expires_at: @access_token.expires_at
        })
      end

      def raw_info
        fields = ['id', 'email-address', 'first-name', 'last-name', 'headline', 'location', 'industry', 'picture-url', 'public-profile-url']
        @raw_info ||= access_token.get("/v1/people/~:(#{fields.join(',')})?format=json")
      end

      def skip_info?
        false
      end

      def info_options
        params = {:appsecret_proof => appsecret_proof}
        params.merge!({:fields => @options[:info_fields]}) if @options[:info_fields]
        params.merge!({:locale => @options[:locale]}) if @options[:locale]

        {:params => params}
      end

      def appsecret_proof
        @appsecret_proof ||= OpenSSL::HMAC.hexdigest(OpenSSL::Digest::SHA256.new, @secret, @access_token.token)
      end

      def credentials
        hash = {'token' => @access_token.token}
        hash.merge!('refresh_token' => @access_token.refresh_token) if @access_token.expires? && @access_token.refresh_token
        hash.merge!('expires_at' => @access_token.expires_at) if @access_token.expires?
        hash.merge!('expires' => @access_token.expires?)
        hash
      end

      private

      def user_name
        name = "#{raw_info['firstName']} #{raw_info['lastName']}".strip
        name.empty? ? nil : name
      end
    end
  end
end
