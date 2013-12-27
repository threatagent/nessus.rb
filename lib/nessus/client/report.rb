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
        hostname_to_report_items_arr = report_findings.map do |hostname, reports|
          [
            hostname,
            reports.map do |report_item|
                {
                  'pluginid' => report_item['pluginid'],
                  'pluginname' => report_item['pluginname'],
                  'severity' => report_item['severity']
                }
            end
          ]
        end

        hostname_to_report_items = Hash[hostname_to_report_items_arr]

        pluginid_arr = hostname_to_report_items.values.flatten.uniq.sort_by { |report_item| report_item['pluginid'] }.map do |report_item|
          [
            report_item['pluginid'],
            {
              'hosts' => hostname_to_report_items.map { |hostname, reports|
                if reports.uniq.map { |other_report_item| other_report_item['pluginid'] }.include? report_item['pluginid']
                  hostname
                end
              }.compact.sort,
              'pluginname' => report_item['pluginname'],
              'severity' => report_item['severity']
            }
          ]
        end

        pluginid_to_hostnames = Hash[pluginid_arr]
      end

      def report_item(report_findings, hostname, plugin_id)
        report_findings[hostname].find_all do |report_item|
          report_item['pluginid'].eql? plugin_id
        end
      end

      def report_parse(report)
        doc = Nokogiri::XML(report)
        report_data = doc.css('ReportHost').map { |report_host|
          {
            report_host.attributes['name'].value => report_host.css('ReportItem').map { |report_item|
            report_item.map { |key, attribute|
              {
                key.downcase => attribute
              }
            }.inject(:merge).merge({
              'data' => %w[
                description fname
                  plugin_modification_date plugin_name
                  plugin_publication_date plugin_type
                  risk_factor script_version
                  solution synopsis
                  plugin_output
                ].map { |report_subitem|
                  report_item.css(report_subitem).map { |node|
                    {
                      node.name => node.text
                    }
                  }
                }.flatten.inject(:merge)
              })
            }
          }
        }.inject(:merge).sort_by { |k, v| k }

        Hash[report_data]
      end

      # @!endgroup
    end
  end
end
