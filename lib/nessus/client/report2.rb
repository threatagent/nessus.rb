module Nessus
  class Client
    # @author Erran Carey <me@errancarey.com>
    module Report2
      # POST /report/ports
      #
      # @param [String] report unique identifier
      # @param [String] hostname name of host to display open ports for
      #
      # @return an object containing a list of open ports on a specified host
      def report2_hosts(report)
        arguments = {
                      :report => report,
                    }
        response = post '/report2/hosts', arguments
        response
      end
    end
  end
end
