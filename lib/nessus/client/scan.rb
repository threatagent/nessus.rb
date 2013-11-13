module Nessus
  class Client
    # @author Erran Carey <me@errancarey.com>
    module Scan
      # POST /scan/new
      #
      # @param [String] target a string that contains the scan target(s)
      # @param [Fixnum] policy_id a numeric ID that references the policy to use
      # @param [String] scan_name the name to assign to this scan
      # @param [Fixnum] seq a unique identifer for the specific request
      #
      # @return [Hash] the newly created scan object
      def create_scan(target, policy_id, scan_name, seq = nil)
        payload = {
          :target => target,
          :policy_id => policy_id,
          :scan_name => scan_name,
          :json => 1
        }
        payload[:seq] = seq if seq
        resp = post '/scan/new', payload

        if resp['reply']['status'].eql? 'ERROR'
          raise Nessus::UnknownError, resp['reply']['contents']
        end

        resp['reply']['contents'] # ['scan']
      end

      # GET /scan/list
      #
      # @return [Array<Hash>] an array of scan hashes
      def scans
        resp = get '/scan/list'

        resp['reply']['contents']
      end
    end
  end
end
