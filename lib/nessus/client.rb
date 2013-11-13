require 'faraday'
require 'json'

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
    include Nessus::Client::Scan

    class << self
      attr_accessor :verify_ssl
    end

    attr_reader :connection

    def initialize(host, login = nil, password = nil)
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
      json = JSON.parse(resp.body)

      if json['reply']['status'].eql? 'OK'
        connection.headers[:cookie][:token] = json['reply']['contents']['token']
      end

      true
    end

    def inspect
      inspected = super

      token = connection.headers[:cookie][:token]
      if token
        inspected.gsub token, ('*' * token.length)
      end

      inspected
    end

    def get(url, params = {}, headers = {})
      require 'pry'
      binding.pry

      JSON.parse(resp.body)
      # connection.params.merge(params)
      # connection.headers.merge(params)
      # connection.get(url, )
    end

    def post(url, payload, *args)
      connection.post(url, payload, *args)
    end
  end
end
