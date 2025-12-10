# frozen_string_literal: true

# name: discourse-ip-anonymizer
# about: Anonymizes IP addresses using deterministic hashing
# version: 0.0.1
# authors: Jahan Gagan
# url: TODOhttps://github.com/jahan-ggn/discourse-ip-anonymizer

enabled_site_setting :discourse_ip_anonymizer_enabled

module ::DiscourseIpAnonymizer
  PLUGIN_NAME = "discourse-ip-anonymizer"
end

require_relative "lib/discourse_ip_anonymizer/engine"

class ::IpAnonymizerMiddleware
  def initialize(app)
    @app = app
  end
  
  def call(env)
    real_ip = env['REMOTE_ADDR']
    puts "BEFORE: Real IP = #{real_ip}"
    
    anonymized_ip = anonymize_ip(real_ip)
    # env['REMOTE_ADDR'] = anonymized_ip
    env['action_dispatch.remote_ip'] = anonymized_ip
    
    puts "AFTER: Anonymized IP = #{anonymized_ip}"

    puts "SET action_dispatch.remote_ip = #{env['action_dispatch.remote_ip']}"
    
    @app.call(env)
  end
  
  private
  
  def anonymize_ip(real_ip)
    secret_key = SiteSetting.ip_anonymizer_secret_key
    hmac = OpenSSL::HMAC.hexdigest('SHA256', secret_key, real_ip)
    hex_parts = hmac[0..7].scan(/.{2}/)
    ip_parts = hex_parts.map { |hex| hex.to_i(16) }
    ip_parts.join('.')
  end
end

after_initialize do
end

Discourse::Application.initializer "ip_anonymizer_middleware", before: :build_middleware_stack do |app|
  app.middleware.use ::IpAnonymizerMiddleware
end