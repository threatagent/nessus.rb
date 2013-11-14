module Nessus
  class Client
    # @author Erran Carey <me@errancarey.com>
    module Policy
      # GET /policy/list
      def policy_list
        resp = get '/policy/list'
        resp['reply']['contents']['policies']['policy']
      end
    end
  end
end
