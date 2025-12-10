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
    # Anonymize forwarded IP first (from proxy/nginx)
    if env['HTTP_X_FORWARDED_FOR']
      real_forwarded_ip = env['HTTP_X_FORWARDED_FOR'].split(',').first.strip
      anonymized_forwarded = anonymize_ip(real_forwarded_ip)
      env['HTTP_X_FORWARDED_FOR'] = anonymized_forwarded
      Rails.logger.warn "FORWARDED - BEFORE: #{real_forwarded_ip}, AFTER: #{anonymized_forwarded}"
    end
    
    # Anonymize REMOTE_ADDR
    real_ip = env['REMOTE_ADDR']
    Rails.logger.warn "REMOTE_ADDR - BEFORE: #{real_ip}"
    
    anonymized_ip = anonymize_ip(real_ip)
    env['action_dispatch.remote_ip'] = anonymized_ip
    
    Rails.logger.warn "REMOTE_ADDR - AFTER: #{anonymized_ip}"
    
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
