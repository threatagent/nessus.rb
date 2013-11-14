module Nessus
  # @todo add more descriptive error classes

  # 403
  Forbidden = Class.new(StandardError)
  # *
  UnknownError = Class.new(StandardError)
end
