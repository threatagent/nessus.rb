require 'cgi'
require 'faraday'
require 'json'
require 'pry'
require 'nessus/client/file'
require 'nessus/client/policy'
require 'nessus/client/report'
require 'nessus/client/report2'
require 'nessus/client/scan'

module Nessus
  class Client
    include Nessus::Client::File
    include Nessus::Client::Policy
    include Nessus::Client::Report
    include Nessus::Client::Report2
    include Nessus::Client::Scan

    class << self
      attr_accessor :verify_ssl
    end

    attr_reader :connection

    def initialize(host)
      @verify_ssl = Nessus::Client.verify_ssl.nil? ? true : false
      @connection = Faraday.new host, :ssl => { :verify => @verify_ssl }
    end

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

    def inspect
      inspected = super

      if connection
        cookie = CGI::Cookie.parse(connection.headers[:cookie])

        if cookie.keys.include? 'token'
          inspected.gsub cookie['token'], ('*' * cookie['token'].length)
        end
      end

      inspected
    end

    def get(url, params = {}, headers = {})
      params ||= {}
      params[:json] ||= 1

      params  = connection.params.merge(params)
      headers = connection.headers.merge(headers)
      resp    = connection.get url, params, headers
      JSON.parse(resp.body)
    end

    def post(url, payload = nil, headers = nil, &block)
      payload ||= {}
      payload[:json] ||= 1

      resp = connection.post(url, payload, headers, &block)
      JSON.parse(resp.body)
    end
  end
end
