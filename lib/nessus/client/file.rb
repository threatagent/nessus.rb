module Nessus
  class Client
    # @author Erran Carey <me@errancarey.com>
    module File
      # GET /file/report/download
      #
      # @param [String] uuid the unique ID (name) of the report to download
      # @return [String] the specified report as an XML string
      def report_download(uuid)
        resp = connection.get '/file/report/download', :report => uuid
        resp.body
      end
    end
  end
end
