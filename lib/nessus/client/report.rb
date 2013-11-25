module Nessus
  class Client
    # @author Erran Carey <me@errancarey.com>
    module Report
      # GET /report/list
      #
      # @return [Array<Hash>] an array of report hashes
      def report_list
        response = get '/report/list'
        response['reply']['contents']['reports']['report']
      end

      # GET /file/xslt/list
      #
      # @return [Array<Hash>] an object containing a list of XSLT transformations
      def xslt_list
        response = post '/file/xslt/list'
        response['reply']['contents']
      end

      # POST /report/delete
      #
      # @param [String] report unique identifier
      #
      # @return status OK if successful
      def report_delete(report)
        response = post '/report/delete', :report => report
        response['reply']['contents']
      end

      # POST /report/hosts
      #
      # @param [String] report unique identifier
      #
      # @return status OK if successful
      def report_hosts(report)
        response = get '/report/hosts', :report => report
        response['reply']['contents']
      end

      # POST /report/ports
      #
      # @param [String] report unique identifier
      # @param [String] hostname name of host to display open ports for
      #
      # @return an object containing a list of open ports on a specified host
      def report_ports(report, hostname)
        arguments = {
                      :report => report,
                      :hostname => hostname
                    }
        response = post '/report/ports', arguments
        response['reply']['contents']
      end

      # POST /report/details
      #
      # @param [String] report unique identifier
      # @param [String] hostname to display scan results for
      # @param [String] port to display scan results for
      # @param [String] protocol of open port on host to display scan details for
      #
      # @return an object containing a details of specified scan
      def report_details(report, hostname, port, protocol)
        arguments = {
                       :report => report,
                       :hostname => hostname,
                       :port => port,
                       :protocol => protocol
                     }
        response = post '/report/details', arguments
        response['reply']['contents']
      end

      # POST /report/tags
      #
      # @param [String] report unique identifier
      # @param [String] hostname name of host to display open ports for
      #
      # @return an object containing a list of tags for the specified host
      def report_tags(report, hostname)
        arguments = {
                      :report => report,
                      :hostname => hostname
                    }
        response = post '/report/tags', arguments
        response['reply']['contents']
      end

      # @!group Report Auxiliary methods
      #
      # @return [Array] of hostnames/IP addresses
      def report_hostlist(report)
        hostlist = report_hosts(report)['hostlist']['host']
        if hostlist.is_a? Array
          hostlist.map {|host| host['hostname']}
        else
          [hostlist['hostname']]
        end
      end

      # @return [Array<Array>] of port numbers and protocol
      def report_portlist(report, ip_address)
        ports = report_ports(report, ip_address)['portlist']['port']
        if ports.is_a? Hash
          ports = [ports]
        end
        ports.map do |port|
          [port['portnum'], port['protocol']]
        end
      end

      # @return [Array<Hash>] reports by readablename regex
      def report_find_all(name)
        report_list.find_all do |report|
          report['readablename'] =~ /#{name}/i
        end
      end

      def report_readablename(name)
        report_list.find{|report| report['name'].eql? name}['readablename']
      end
      # @!endgroup
    end
  end
end
