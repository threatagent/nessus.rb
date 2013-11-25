module Nessus
  class Client
    # @author Erran Carey <me@errancarey.com>
    module Policy
      # GET /policy/list
      def policy_list
        response = get '/policy/list'
        response['reply']['contents']['policies']['policy']
      end

      # @!group Policy Auxiliary Methods

      # @return [Array<Array<String>>] an object containing a list of policies
      # and their policy IDs
      def policies
        policy_list.map do |policy|
          [policy['policyname'], policy['policyid']]
        end
      end

      # @return [String] looks up policy ID by policy name
      def policy_id_by_name(name)
        policy_list.find{|policy| policy['policyname'].eql? name}['policyid']
      rescue
        nil
      end

      # @return [String] looks up policy name by policy ID
      def policy_name_by_id(id)
        policy_list.find{|policy| policy['policyid'].eql? id}['policyname']
      rescue
        nil
      end

      #@!endgroup
    end
  end
end
