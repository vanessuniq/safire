require 'erb'

module SafireCompliance
  # Renders the Phase 2 (app launch) report hash as one static HTML page (no external assets).
  class AppLaunchHTMLReport
    include ERB::Util

    TEMPLATE = <<~HTML.freeze
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="utf-8">
        <title>Safire × Inferno SMART STU2.2 App Launch</title>
        <style>
          body { font-family: system-ui, sans-serif; margin: 2rem; color: #222; }
          table { border-collapse: collapse; width: 100%; margin-bottom: 1.5rem; }
          th, td { border: 1px solid #ccc; padding: .4rem .6rem; text-align: left; vertical-align: top; }
          th { background: #f4f4f4; }
          code { font-size: .9em; }
          .pass { color: #1a7f37; font-weight: 600; }
          .fail, .error { color: #cf222e; font-weight: 600; }
          .skip, .omit, .wait { color: #9a6700; font-weight: 600; }
          ul { margin: 0; padding-left: 1.2rem; }
          section { border-top: 2px solid #888; margin-top: 2rem; }
        </style>
      </head>
      <body>
        <h1>Safire × Inferno: SMART App Launch STU2.2 (authorization code)</h1>
        <p>Overall: <span class="<%= h(report[:overall]) %>"><%= h(report[:overall]) %></span></p>
        <% if report[:error] %><p class="error">Harness error: <%= h(report[:error]) %></p><% end %>
        <table>
          <% report[:metadata].each do |key, value| %>
          <tr><th><%= h(key) %></th><td><code><%= h(value) %></code></td></tr>
          <% end %>
        </table>
        <table>
          <tr><th>Scenario</th><th>Kind</th><th>Launch</th><th>client_type option</th><th>Outcome</th></tr>
          <% report[:scenarios].each do |s| %>
          <tr><td><a href="#<%= h(s[:id]) %>"><%= h(s[:id]) %></a></td><td><%= h(s[:kind]) %></td>
              <td><%= h(s[:launch]) %></td><td><code><%= h(s[:client_type]) %></code></td>
              <td class="<%= h(s[:outcome]) %>"><%= h(s[:outcome]) %></td></tr>
          <% end %>
        </table>

        <% report[:scenarios].each do |s| %>
        <section id="<%= h(s[:id]) %>">
          <h2><%= h(s[:id]) %> (<%= h(s[:kind]) %>): <span class="<%= h(s[:outcome]) %>"><%= h(s[:outcome]) %></span></h2>
          <p>Inferno session <code><%= h(s[:test_session_id]) %></code>. Expected: <code><%= h(s[:expected]) %></code></p>
          <% if s[:note] %><p>Note: <%= h(s[:note]) %></p><% end %>
          <% if s[:error] %><p class="error"><%= h(s[:error]) %></p><% end %>
          <% unless s[:reasons].to_a.empty? %><ul><% s[:reasons].each do |r| %><li><%= h(r) %></li><% end %></ul><% end %>

          <h3>Inferno-driven results</h3>
          <table>
            <tr><th>Inferno id</th><th>Result</th><th>Message</th><th>Inferno messages</th></tr>
            <% s[:inferno_results].each do |r| %>
            <tr>
              <td><code><%= h(r[:id]) %></code></td>
              <td class="<%= h(r[:result]) %>"><%= h(r[:result]) %></td>
              <td><%= h(r[:result_message]) %></td>
              <td><ul><% r[:messages].each do |m| %><li><%= h(m['type']) %>: <%= h(m['message']) %></li><% end %></ul></td>
            </tr>
            <% end %>
          </table>

          <h3>Local Safire checks (not Inferno assertions)</h3>
          <table>
            <tr><th>Check</th><th>Result</th><th>Detail</th></tr>
            <% s[:local_checks].each do |c| %>
            <tr>
              <td><code><%= h(c[:id]) %></code><br><%= h(c[:title]) %></td>
              <td class="<%= h(c[:result]) %>"><%= h(c[:result]) %></td>
              <td><pre><%= h(c[:detail]) %></pre></td>
            </tr>
            <% end %>
          </table>

          <h3>Harness observations</h3>
          <p>User-agent hops (query strings omitted):</p>
          <ul><% s.dig(:harness, :user_agent_hops).to_a.each do |hop| %><li><code><%= h(hop[:status]) %> <%= h(hop[:url]) %></code></li><% end %></ul>
          <p>FHIR read with the issued token (performed by the harness, not Safire):
             HTTP <%= h(s.dig(:harness, :fhir_read_status) || 'not attempted') %></p>
        </section>
        <% end %>
      </body>
      </html>
    HTML

    # @param report [Hash] report built by {AppLaunchRun}
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
