module Nessus
  class Client
    module Report
      def reports
        resp = get '/reports/list'
        resp['reply']['contents']['reports']['report']
      end
    end
  end
end
