require 'cgi'
require 'faraday'
require 'json'
require 'nessus/client/file'
require 'nessus/client/policy'
require 'nessus/client/report'
require 'nessus/client/report2'
require 'nessus/client/scan'
require 'nessus/error'
require 'nessus/version'

module Nessus
  # @author Erran Carey <me@errancarey.com>
  class Client
    include Nessus::Client::File
    include Nessus::Client::Policy
    include Nessus::Client::Report
    include Nessus::Client::Report2
    include Nessus::Client::Scan

    class << self
      # @!attribute verify_ssl
      #   @return [Boolean] whether to verify SSL with Faraday (default: true)
      attr_accessor :verify_ssl
    end

    # @!attribute connection
    #   @return [Faraday::Connection]
    attr_reader :connection

    # @param [String] host the base URL to use when connecting to the Nessus API
    def initialize(host)
      @verify_ssl = Nessus::Client.verify_ssl.nil? ? true : false
      @connection = Faraday.new host, :ssl => { :verify => @verify_ssl }
      @connection.headers[:user_agent] = "Nessus.rb v#{Nessus::VERSION}".freeze
    end

    # POST /login
    #
    # @param [String] login the username of the account to use for authentication
    # @param [String] password the password of the account to use for authentication
    def authenticate(login, password)
      payload = {
        :login => login,
        :password => password,
        :json => 1
      }
      resp = post '/login', payload

      if resp['reply']['status'].eql? 'OK'
        connection.headers[:cookie] = "token=#{resp['reply']['contents']['token']}"
      end

      true
    end

#    # @return [String] {#inspect}'s output with a censored session token
#    def inspect
#      inspected = super
#
#      if connection
#        cookie = CGI::Cookie.parse(connection.headers[:cookie])
#
#        if cookie.keys.include? 'token'
#          inspected.gsub cookie['token'].to_s, ('*' * cookie['token'].to_s.length)
#        end
#      end
#
#      inspected
#    end

    # @param [String] url the URL/path to send a GET request using the
    #   connection object and default headers/parameters
    # @param [Hash] params the query parameters to send with the request
    # @param [Hash] headers the headers to send along with the request
    def get(url, params = {}, headers = {})
      params ||= {}
      params[:json] ||= 1

      params  = connection.params.merge(params)
      headers = connection.headers.merge(headers)
      resp    = connection.get url, params, headers
      JSON.parse(resp.body)
    end

    # @param [String] url the URL/path to send a GET request using the
    #   connection object and default headers/payload
    # @param [Hash] payload the JSON body to send with the request
    # @param [Hash] headers the headers to send along with the request
    def post(url, payload = nil, headers = nil, &block)
      payload ||= {}
      payload[:json] ||= 1

      resp = connection.post(url, payload, headers, &block)
      JSON.parse(resp.body)
    end
  end
end
