module Nessus
  class Client
    # @author Erran Carey <me@errancarey.com>
    module Policy
      # GET /policy/list
      def policies
        resp = get '/policy/list'
        resp['reply']['contents']['policies']['policy']
      end
    end
  end
end
