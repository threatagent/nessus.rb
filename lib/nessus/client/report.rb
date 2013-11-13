require 'nessus/client/report2'

module Nessus
  class Client
    module Report
      include Nessus::Client::Report2

      def reports
        resp = get '/reports/list'
        resp['reply']['contents']['reports']['report']
      end
    end
  end
end
