module Nessus
  class Client
    module Report
      def reports
        resp = get '/report/list'

        resp['reply']['contents']['reports']['report']
      end
    end
  end
end
