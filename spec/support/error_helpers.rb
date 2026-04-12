module ErrorHelpers
  # Captures a raised error of the given class; returns nil if none is raised.
  # Needed because RSpec's `end.to raise_error(Klass) do |e|` is a multi-line block chain
  # (Style/MultilineBlockChain offense), so we capture manually instead.
  def capture_error(klass)
    yield
    nil
  rescue klass => e
    e
  end
end
