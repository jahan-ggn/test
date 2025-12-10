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

class ::AnonymizedIpWrapper
  def initialize(original_ip, anonymized_ip)
    @original_ip = original_ip
    @anonymized_ip = anonymized_ip
  end
  
  def to_s
    @anonymized_ip
  end
  
  def to_str
    @anonymized_ip
  end
  
  def inspect
    @anonymized_ip
  end
  
  def method_missing(method, *args, &block)
    @anonymized_ip.send(method, *args, &block)
  end
  
  def respond_to_missing?(method, include_private = false)
    @anonymized_ip.respond_to?(method, include_private) || super
  end
end

class ::IpAnonymizerMiddleware
  def initialize(app)
    @app = app
  end
  
  def call(env)
    # Let all middleware run first (including ActionDispatch::RemoteIp)
    status, headers, body = @app.call(env)
    
    # Now anonymize the IP that was calculated
    if env['action_dispatch.remote_ip']
      original_ip = env['action_dispatch.remote_ip'].to_s
      anonymized_ip = anonymize_ip(original_ip)
      
      Rails.logger.warn "IP ANONYMIZATION: #{original_ip} -> #{anonymized_ip}"
      
      # Wrap it so it behaves like the original object
      env['action_dispatch.remote_ip'] = ::AnonymizedIpWrapper.new(original_ip, anonymized_ip)
    end
    
    [status, headers, body]
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
