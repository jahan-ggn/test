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
    hmac = OpenSSL::HMAC.hexdigest('SHA256', secret_key, real_ip)
    hex_parts = hmac[0..7].scan(/.{2}/)
    ip_parts = hex_parts.map { |hex| hex.to_i(16) }
    result = ip_parts.join('.')
    Rails.logger.warn "[IP-ANON] Final anonymized IP: #{result}"
    result
  end
  
  module RackRequestIpPatch
    def ip
      Rails.logger.warn "[IP-ANON] RackRequestIpPatch#ip method called"
      real_ip = super
      Rails.logger.warn "[IP-ANON] Real IP from super: #{real_ip}"
      anonymized = ::DiscourseIpAnonymizer.anonymize_ip(real_ip)
      Rails.logger.warn "[IP-ANON] Returning anonymized IP: #{anonymized}"
      anonymized
    end
  end
end

require_relative "lib/discourse_ip_anonymizer/engine"

after_initialize do
  Rails.logger.warn "[IP-ANON] Patching Rack::Request"
  Rack::Request.prepend(::DiscourseIpAnonymizer::RackRequestIpPatch)
  Rails.logger.warn "[IP-ANON] Rack::Request ancestors: #{Rack::Request.ancestors.first(5).join(', ')}"
end
