module Nessus
  # @todo add more descriptive error classes

  # HTTP error 403
  Forbidden = Class.new(StandardError)
  # Catch all for HTTP errors
  UnknownError = Class.new(StandardError)
end
