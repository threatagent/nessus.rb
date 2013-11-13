module Nessus
  class Client
    module File
      def download_report(uuid)
        connection.get '/file/report/download', :report => uuid
      end
    end
  end
end
