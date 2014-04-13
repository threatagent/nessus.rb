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

      # GET /file/xslt/list
      #
      # @return [Array<Hash>] an object containing a list of XSLT transformations
      def xslt_list
        response = post '/file/xslt/list'
        response['reply']['contents']
      end
    end
  end
end
