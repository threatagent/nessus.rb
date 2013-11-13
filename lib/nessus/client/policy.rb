module Nessus
  class Client
    module Policy
      def policies
        resp = get '/policy/list'
        resp['reply']['contents']['policies']['policy']
      end
    end
  end
end
