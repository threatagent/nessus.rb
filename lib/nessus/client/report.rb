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
      rescue
        []
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
      rescue
        []
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
      def report_find_by_name(name)
        report_list.find_all do |report|
          report['name'] == name
        end
      end

      def report_find_by_readablename(readablename)
        report_list.find_all do |report|
          report['readablename'] == readablename
        end
      end

      def report_find_all(name)
        report_list.find_all do |report|
          report['readablename'] =~ /#{name}/i
        end
      end

      def report_readablename(name)
        report_list.find{|report| report['name'].eql? name}['readablename']
      end

      def report_findings(report)
        hosts = report_hostlist(report)
        ports = hosts.map do |host|
          report_portlist(report, host)
        end

        hosts_and_ports= hosts.zip(ports).map do |key, value|
          {
            key => value
          }
        end

        hosts_and_ports_hash = hosts_and_ports.inject(:merge)
        report_element_array = hosts_and_ports_hash.map do |key, values|
          {
            key => values.map do |value|
              {
                'port_number' => value.first,
                'port_type' => value.last,
                'findings' => report_details(report, key, value.first, value.last)
              }
            end
          }
        end
        report_hash = report_element_array.inject(:merge)
        json_report = JSON.pretty_generate(report_hash)
      end

      def report_plugin_summary(report_findings)
        ip_findings_arr = report_findings.map do |hostname, reports|
          [
            reports.map { |report|
                if report['findings']['portdetails']['reportitem'].is_a? Hash
                  {
                    'plugin_id' => report['findings']['portdetails']['reportitem']['pluginid'],
                    'plugin_name' => report['findings']['portdetails']['reportitem']['pluginname'],
                    'severity' => report['findings']['portdetails']['reportitem']['severity'],
                  }
                else
                  report['findings']['portdetails']['reportitem'].map do |report_item|
                    {
                      'plugin_id' => report_item['pluginid'],
                      'plugin_name' => report_item['pluginname'],
                      'severity' => report_item['severity']
                    }
                  end
                end
            }.flatten,
            hostname
          ]
        end
        ip_findings = Hash[ip_findings_arr]

        plugin_id_arr = ip_findings.keys.flatten.uniq.map do |ip_finding|
          [
            ip_finding['plugin_id'],
            {
              'hosts' => ip_findings.map { |ids, hostname|
                           if ids.map { |id| id['plugin_id'] }.include? ip_finding['plugin_id']
                             hostname
                           end
                         }.compact,
              'plugin_name' => ip_finding['plugin_name'],
              'severity' => ip_finding['severity']
            }
          ]
        end
        plugin_id_to_hostname = Hash[plugin_id_arr]
        plugin_id_to_hostname.sort_by { |id, s| s['severity'] }
      end

      def report_item(report_findings, host, plugin_id)
        report_findings[host].map { |report|
          if report['findings']['portdetails']['reportitem'].is_a? Hash
            if report['findings']['portdetails']['reportitem']['pluginid'].eql? plugin_id
              report['findings']['portdetails']['reportitem']
            end
          else
            report['findings']['portdetails']['reportitem'].find_all do |report_item|
              if report_item['pluginid'].eql? plugin_id
                report_item
              end
            end
          end
        }.flatten.compact
      end

      # @!endgroup
    end
  end
end
