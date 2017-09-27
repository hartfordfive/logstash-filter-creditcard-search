# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

# This  filter will search incoming events for potential credit card 
# numbers.  If found, they will be tagged with 'creditcard'
#
# It is only intended to be used as an .
class LogStash::Filters::CreditcardSearch < LogStash::Filters::Base

  # The filter can be used simply like this out of the box
  #
  # filter {
  #    creditcard_search { }
  # }
  #
  config_name "creditcard_search"
  
  # Ignore the following fields from the search (used to eliminate know cases of false-positives)
  config :ignore_fields, :validate => :array, :default => []
  # Add the following tag in the case where a positive match is found
  config :tag_on_success, :validate => :array, :default => ["creditcard"]
  # The regular expression to use for searching for potential credit card numbers
  config :detection_regexp, :validate => :string, :default => "[^0-9]+((?:4[0-9]{12}(?:[0-9]{3})?|[25][1-7][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11}))[^0-9]+"

  public
  def register
    # Add instance variables 
  end # def register

  public
  def filter(event)

    return unless filter?(event)
    
    if @ignore_fields.size >= 1
      verification_event =  event.clone
      @ignore_fields.each do |k|
        verification_event.remove(k)
      end
      serialized_event = verification_event.to_hash.to_s.gsub(' ','')
    else
      serialized_event = event.to_hash.to_s.gsub(' ','')
    end

    matches = /#{@detection_regexp}/.match(serialized_event)
    if matches && luhn_check(matches[0])
      @tag_on_success.each{|tag| event.tag(tag)}
    end
      
  end # def filter

  def luhn_check(str)
    str
      .chars       # Break into individual digits
      .map(&:to_i) # map each character by calling #to_i on it
      .reverse     # Start from the end
      .map.with_index { |x, i| i.odd? ? x * 2 : x } # Double every other digit
      .map { |x| x > 9 ? x - 9 : x }  # If > 9, subtract 9 (same as adding the digits)
      .inject(0, :+) % 10 == 0        # Check if multiple of 10
  end # def luhn_check

end # class LogStash::Filters::CreditcardSearch
