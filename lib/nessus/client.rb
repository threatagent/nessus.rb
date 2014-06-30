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
    def initialize(host, login = nil, password = nil, connection_options = {})
      connection_options[:ssl] ||= {}
      connection_options[:ssl][:verify] ||= Nessus::Client.verify_ssl.nil? || Nessus::Client.verify_ssl

      @connection = Faraday.new host, connection_options
      @connection.headers[:user_agent] = "Nessus.rb v#{Nessus::VERSION}".freeze

      # Allow passing a block to Faraday::Connection
      yield @connection if block_given?

      authenticate(login, password) if login && password
    end

    # POST /login
    #
    # @param [String] login the username of the account to use for authentication
    # @param [String] password the password of the account to use for authentication
    def authenticate(login, password)
      @login    = login
      @password = password

      payload = {
        :login => login,
        :password => password,
        :json => 1,
      }
      resp = connection.post '/login', payload
      resp = JSON.parse(resp.body)

      if resp['reply']['status'].eql? 'OK'
        connection.headers[:cookie] = "token=#{resp['reply']['contents']['token']}"
      end

      true
    end
    alias_method :login, :authenticate

    # POST /logout
    #
    # @param [String] login the username of the account to use for authentication
    # @param [String] password the password of the account to use for authentication
    def logout
      resp = post '/logout'

      if resp['reply']['status'].eql? 'OK'
        if connection.headers[:cookie].include? 'token='
          connection.headers.delete(:cookie)
        else
          # TODO: Instead of warning the user
          # and deleting the cookies anyway delete only the token

          $stdout.puts 'Deleting cookies...'
          connection.headers.delete(:cookie)
        end
      end

      true
    end

    def authenticated?
      headers = connection.headers
      !!headers[:cookie] && headers[:cookie].include?('token=')
    end

    # @param [String] url the URL/path to send a GET request using the
    #   connection object and default headers/parameters
    # @param [Hash] params the query parameters to send with the request
    # @param [Hash] headers the headers to send along with the request
    def get(url, params = {}, headers = {})
      retries ||= 0

      unless authenticated?
        fail Nessus::Unauthorized, 'Unable to detect a session token cookie, use #authenticate before sending any other requests'
      end

      params ||= {}
      params[:json] = 1

      resp    = connection.get url, params, headers
      fail Nessus::Unauthorized if resp.status == 401
      fail Nessus::Forbidden if resp.status == 403

      JSON.parse(resp.body)
    rescue Nessus::Unauthorized, Nessus::Forbidden
      if retries < 1
        retries += 1
        authenticate(@login, @password) if @login && @password
        retry
      else
        raise Nessus::Forbidden, 'Unable to automatically reauthenticate'
      end
    end

    # @param [String] url the URL/path to send a GET request using the
    #   connection object and default headers/payload
    # @param [Hash] payload the JSON body to send with the request
    # @param [Hash] headers the headers to send along with the request
    def post(url, payload = nil, headers = nil, &block)
      retries ||= 0

      unless authenticated?
        fail Nessus::Unauthorized, 'Unable to detect a session token cookie, use #authenticate before sending any other requests'
      end

      payload ||= {}
      payload[:json] = 1

      resp = connection.post(url, payload, headers, &block)
      fail Nessus::Unauthorized if resp.status == 401
      fail Nessus::Forbidden if resp.status == 403

      JSON.parse(resp.body)
    rescue Nessus::Unauthorized, Nessus::Forbidden
      if retries < 1
        retries += 1
        authenticate(@login, @password) if @login && @password
        retry
      else
        raise Nessus::Forbidden, 'Unable to automatically reauthenticate'
      end
    end
  end
end
