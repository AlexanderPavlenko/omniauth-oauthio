module Oauthio
  module Providers
    class Google
      include Base

      def initialize(access_token, secret, options)
        @access_token = access_token
        @secret = secret
        @options = options
      end

      def uid
        raw_info['id'] || verified_email
      end

      def info
        prune!({
                 :name => raw_info['name'],
                 :email => verified_email,
                 :first_name => raw_info['given_name'],
                 :last_name => raw_info['family_name'],
                 :image => image_url(@options),
                 :urls => {
                   'Google' => raw_info['link']
                 }
               })
      end

      def extra
        hash = {}
        hash[:id_token] = @access_token['id_token']
        hash[:raw_info] = raw_info unless skip_info?
        prune! hash
      end

      def raw_info
        @raw_info ||= @access_token.get('https://www.googleapis.com/oauth2/v1/userinfo')
      end

      def skip_info?
        false
      end

      def image_url(options)
        original_url = raw_info['picture']
        return original_url if original_url.nil? || (!options[:image_size] && !options[:image_aspect_ratio])

        image_params = []
        if options[:image_size].is_a?(Integer)
          image_params << "s#{options[:image_size]}"
        elsif options[:image_size].is_a?(Hash)
          image_params << "w#{options[:image_size][:width]}" if options[:image_size][:width]
          image_params << "h#{options[:image_size][:height]}" if options[:image_size][:height]
        end
        image_params << 'c' if options[:image_aspect_ratio] == 'square'

        params_index = original_url.index('/photo.jpg')
        original_url.insert(params_index, ('/' + image_params.join('-')))
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

      def verified_email
        raw_info['verified_email'] ? raw_info['email'] : nil
      end
    end
  end
end
