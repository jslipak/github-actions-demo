require "json"
require "net/http"
require "uri"

uri = URI("http://127.0.0.1:3000/health")
deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + 30

begin
  response = Net::HTTP.start(uri.host, uri.port, open_timeout: 1, read_timeout: 2) do |http|
    http.get(uri.request_uri)
  end
rescue Errno::ECONNREFUSED, Net::OpenTimeout, Net::ReadTimeout
  if Process.clock_gettime(Process::CLOCK_MONOTONIC) >= deadline
    server_log = File.read("/tmp/s10-rails-server.log") if File.file?("/tmp/s10-rails-server.log")
    raise "Rails server did not become ready. Server log:\n#{server_log}"
  end

  sleep 0.2
  retry
end

raise "expected HTTP 200, got #{response.code}" unless response.code == "200"

payload = JSON.parse(response.body)
expected = { "status" => "ok", "scenario" => "S0", "framework" => "Ruby on Rails" }
raise "unexpected health response: #{payload}" unless payload == expected

puts "S10 HTTP smoke test passed: #{response.code} #{payload}"
