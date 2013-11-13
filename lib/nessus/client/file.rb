module Nessus
  class Client
    module File
      def download_report(uuid)
        get '/file/report/download', :report => uuid
      end
    end
  end
end
