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
    secret_key = SiteSetting.ip_anonymizer_secret_key
    hmac = OpenSSL::HMAC.hexdigest('SHA256', secret_key, real_ip)
    hex_parts = hmac[0..7].scan(/.{2}/)
    ip_parts = hex_parts.map { |hex| hex.to_i(16) }
    result = ip_parts.join('.')
    result
  end
  
  module RackRequestIpPatch
    def ip
      return super unless SiteSetting.discourse_ip_anonymizer_enabled
      
      real_ip = super
      Rails.logger.warn "[IP-ANON] Before: #{real_ip}"
      anonymized = ::DiscourseIpAnonymizer.anonymize_ip(real_ip)
      Rails.logger.warn "[IP-ANON] After: #{anonymized}"
      anonymized
    end
  end

  module ActionDispatchRequestRemoteIpPatch
    def remote_ip
      return super unless SiteSetting.discourse_ip_anonymizer_enabled
      
      real_ip = super
      Rails.logger.warn "[IP-ANON] Before: #{real_ip}"
      anonymized = ::DiscourseIpAnonymizer.anonymize_ip(real_ip.to_s)
      Rails.logger.warn "[IP-ANON] After: #{anonymized}"
      anonymized
    end
  end
end

require_relative "lib/discourse_ip_anonymizer/engine"

after_initialize do
  Rack::Request.prepend(::DiscourseIpAnonymizer::RackRequestIpPatch)
  ActionDispatch::Request.prepend(::DiscourseIpAnonymizer::ActionDispatchRequestRemoteIpPatch)
end
