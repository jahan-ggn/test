# frozen_string_literal: true

# name: discourse-ip-anonymizer
# about: Anonymizes IP addresses using deterministic hashing
# version: 0.0.1
# authors: Jahan Gagan
# url: https://github.com/jahan-ggn/discourse-ip-anonymizer

enabled_site_setting :discourse_ip_anonymizer_enabled

module ::DiscourseIpAnonymizer
  PLUGIN_NAME = "discourse-ip-anonymizer"
  
  def self.anonymize_ip(real_ip)
    Rails.logger.warn "[IP-ANON] anonymize_ip called with: #{real_ip}"
    secret_key = SiteSetting.ip_anonymizer_secret_key
    Rails.logger.warn "[IP-ANON] Secret key length: #{secret_key&.length}"
    hmac = OpenSSL::HMAC.hexdigest('SHA256', secret_key, real_ip)
    Rails.logger.warn "[IP-ANON] HMAC: #{hmac[0..15]}..."
    hex_parts = hmac[0..7].scan(/.{2}/)
    ip_parts = hex_parts.map { |hex| hex.to_i(16) }
    result = ip_parts.join('.')
    Rails.logger.warn "[IP-ANON] Final anonymized IP: #{result}"
    result
  end
  
  # Patch Rack::Request#ip
  module RackRequestIpPatch
    def ip
      Rails.logger.warn "[IP-ANON] Rack::Request#ip called"
      real_ip = super
      Rails.logger.warn "[IP-ANON] Rack::Request#ip super returned: #{real_ip}"
      anonymized = ::DiscourseIpAnonymizer.anonymize_ip(real_ip)
      Rails.logger.warn "[IP-ANON] Rack::Request#ip returning: #{anonymized}"
      anonymized
    end
  end

  # Patch ActionDispatch::Request#remote_ip
  module ActionDispatchRequestRemoteIpPatch
    def remote_ip
      Rails.logger.warn "[IP-ANON] ActionDispatch::Request#remote_ip called"
      Rails.logger.warn "[IP-ANON] Caller: #{caller[0..2].join(' | ')}"
      real_ip = super
      Rails.logger.warn "[IP-ANON] ActionDispatch::Request#remote_ip super returned: #{real_ip}"
      anonymized = ::DiscourseIpAnonymizer.anonymize_ip(real_ip.to_s)
      Rails.logger.warn "[IP-ANON] ActionDispatch::Request#remote_ip returning: #{anonymized}"
      anonymized
    end
  end
end

require_relative "lib/discourse_ip_anonymizer/engine"

after_initialize do
  Rails.logger.warn "[IP-ANON] === STARTING INITIALIZATION ==="
  
  # Patch Rack::Request
  Rails.logger.warn "[IP-ANON] Patching Rack::Request#ip"
  Rack::Request.prepend(::DiscourseIpAnonymizer::RackRequestIpPatch)
  Rails.logger.warn "[IP-ANON] Rack::Request ancestors: #{Rack::Request.ancestors.first(7).join(', ')}"
  
  # Patch ActionDispatch::Request
  Rails.logger.warn "[IP-ANON] Patching ActionDispatch::Request#remote_ip"
  ActionDispatch::Request.prepend(::DiscourseIpAnonymizer::ActionDispatchRequestRemoteIpPatch)
  Rails.logger.warn "[IP-ANON] ActionDispatch::Request ancestors: #{ActionDispatch::Request.ancestors.first(7).join(', ')}"
  
  Rails.logger.warn "[IP-ANON] === INITIALIZATION COMPLETE ==="
end

