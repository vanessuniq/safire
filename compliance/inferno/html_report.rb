require 'erb'

module SafireCompliance
  # Renders the harness report hash as a single static HTML page (no external assets).
  class HTMLReport
    include ERB::Util

    TEMPLATE = <<~HTML.freeze
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="utf-8">
        <title>Safire × Inferno SMART STU2.2 Backend Services</title>
        <style>
          body { font-family: system-ui, sans-serif; margin: 2rem; color: #222; }
          table { border-collapse: collapse; width: 100%; margin-bottom: 2rem; }
          th, td { border: 1px solid #ccc; padding: .4rem .6rem; text-align: left; vertical-align: top; }
          th { background: #f4f4f4; }
          code { font-size: .9em; }
          .pass { color: #1a7f37; font-weight: 600; }
          .fail, .error { color: #cf222e; font-weight: 600; }
          .skip, .omit, .wait { color: #9a6700; font-weight: 600; }
          ul { margin: 0; padding-left: 1.2rem; }
        </style>
      </head>
      <body>
        <h1>Safire × Inferno: SMART App Launch STU2.2 Backend Services</h1>
        <p>Overall: <span class="<%= h(report[:overall]) %>"><%= h(report[:overall]) %></span></p>
        <table>
          <% report[:metadata].each do |key, value| %>
          <tr><th><%= h(key) %></th><td><code><%= h(value) %></code></td></tr>
          <% end %>
        </table>

        <h2>Inferno-driven results</h2>
        <p>Assertions made by the Inferno test kit acting as the authorization and FHIR server.</p>
        <table>
          <tr><th>Inferno id</th><th>Result</th><th>Message</th><th>Inferno messages</th></tr>
          <% report[:inferno_results].each do |r| %>
          <tr>
            <td><code><%= h(r[:id]) %></code></td>
            <td class="<%= h(r[:result]) %>"><%= h(r[:result]) %></td>
            <td><%= h(r[:result_message]) %></td>
            <td><ul><% r[:messages].each do |m| %><li><%= h(m['type']) %>: <%= h(m['message']) %></li><% end %></ul></td>
          </tr>
          <% end %>
        </table>

        <h2>Local Safire checks (not Inferno assertions)</h2>
        <table>
          <tr><th>Check</th><th>Result</th><th>Detail</th></tr>
          <% report[:local_checks].each do |c| %>
          <tr>
            <td><code><%= h(c[:id]) %></code><br><%= h(c[:title]) %></td>
            <td class="<%= h(c[:result]) %>"><%= h(c[:result]) %></td>
            <td><pre><%= h(c[:detail]) %></pre></td>
          </tr>
          <% end %>
        </table>
        <p>Harness FHIR read with the issued token (performed by the harness, not Safire):
           HTTP <%= h(report.dig(:harness, :fhir_read_status)) %></p>
      </body>
      </html>
    HTML

    # @param report [Hash] report built by {BackendServicesRun}
    def initialize(report)
      @report = report
    end

    # @return [String] HTML document
    def render
      report = @report
      ERB.new(TEMPLATE).result(binding)
    end
  end
end
