module Nessus
  class Client
    # @author Erran Carey <me@errancarey.com>
    module Report
      # GET /report/list
      #
      # @return [Array<Hash>] an array of report hashes
      def reports
        resp = get '/report/list'

        resp['reply']['contents']['reports']['report']
      end
    end
  end
end
