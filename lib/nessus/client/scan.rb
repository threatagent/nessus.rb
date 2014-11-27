module Nessus
  class Client
    # @author Erran Carey <me@errancarey.com>
    module Scan
      # POST /scan/new
      #
      # @param [String] target a string that contains the scan target(s)
      # @param [Fixnum] policy_id a numeric ID that references the policy to use
      # @param [String] scan_name the name to assign to this scan
      # @param [Fixnum] seq a unique identifier for the specific request
      #
      # @return [Hash] the newly created scan object
      def scan_new(target, policy_id, scan_name, seq = nil, description = nil)
        payload = {
          :custom_targets => target,
          :policy_id => policy_id,
          :name => scan_name
        }
        payload[:seq] = seq if seq
        payload[:description] = description if description
        response = post '/scan/new', payload

        if response['error']
          raise Nessus::UnknownError, response['error']
        end

        response['reply']['contents'] # ['scan']
      end

      # GET /scan/list
      #
      # @return [Array<Hash>] an array of scan hashes
      def scan_list
        response = get '/scan/list'
        response['reply']['contents']
      end

      # POST /scan/stop
      #
      # @param [String] scan_uuid unique identifier for the scan
      #
      # @return status OK if successful
      def scan_stop(scan_uuid)
        response = post '/scan/stop', :scan_uuid => scan_uuid
        response['reply']['contents']
      end

      # POST /scan/pause
      #
      # @param [String] scan_uuid unique identifier for the scan
      #
      # @return status OK if successful
      def scan_pause(scan_uuid)
        response = post '/scan/pause', :scan_uuid => scan_uuid
        response['reply']['contents']
      end

      # POST /scan/resume
      #
      # @param [String] scan_uuid unique identifier for the scan
      #
      # @return status OK if successful
      def scan_resume(scan_uuid)
        response = post '/scan/resume', :scan_uuid => scan_uuid
        response['reply']['contents']
      end

      # POST /scan/template/new
      #
      # @param [String] scan template name
      # @param [String] scan policy identifier
      # @param [String] targets for scan template
      #
      # @return status OK if successful
      def scan_template_new(template_name, policy_id, target, seq = nil, start_time = nil, rrules = nil)
        payload = {
          :template_name => template_name,
          :policy_id => policy_id,
          :target => target
        }
        payload[:seq] = seq if seq
        payload[:startTime] = start_time if start_time
        payload[:rRules] = rrules if rrules
        response = post '/scan/template/new', payload

        if response['reply']['status'].eql? 'ERROR'
          raise Nessus::UnknownError, response['reply']['contents']
        end

        response['reply']['contents'] # ['scan']
      end
    end
  end
end
