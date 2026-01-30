# Safire Demo Application

A Sinatra-based web application that demonstrates the features of the Safire gem for SMART on FHIR authorization.

## Features

- **Server Management**: Add, edit, and remove FHIR server configurations with support for public and confidential clients
- **SMART Discovery**: View server capabilities from `/.well-known/smart-configuration` including supported scopes, capabilities, and endpoints
- **Authorization Flows**: Test multiple launch types:
  - Provider Standalone Launch
  - Patient Standalone Launch
  - EHR Launch (requires EHR/portal to initiate)
  - Patient Portal Launch
- **Token Management**: View obtained tokens and test token refresh functionality

## Quick Start

From the project root:

```bash
bin/demo
```

Or from this directory:

```bash
bundle install
bundle exec puma config.ru -p 4567
```

Then visit http://localhost:4567

## Configuration

### Environment Variables

- `PORT` - Server port (default: 4567)
- `SESSION_SECRET` - Session encryption key (auto-generated if not set)

### Adding a FHIR Server

1. Click "Add Server" on the home page
2. Enter the server details:
   - **Name**: Display name for the server
   - **Base URL**: FHIR server base URL
   - **Client ID**: OAuth client ID registered with the server
   - **Client Secret**: (Optional) For confidential clients only
   - **Scopes**: Space or comma-separated list of OAuth scopes

## Demo Workflows

### Testing with SMART Health IT Sandbox (Default Server)

The app comes pre-configured with a SMART Health IT sandbox server for testing.

#### Standalone Launch

1. Select "SMART Health IT RI" from the server list
2. Click "Start Authorization"
3. Choose your settings:
   - **Launch Type**: Provider Standalone or Patient Standalone
   - **Auth Type**: Public Client or Confidential Symmetric
4. Click "Start Authorization"
5. In the SMART sandbox, select a patient and practitioner
6. View the obtained tokens

#### EHR Launch

To test EHR launch with the SMART sandbox:

1. Go to https://launch.smarthealthit.org/
2. Select "EHR Launch" mode
3. Enter `http://localhost:4567/launch` as the App Launch URL
4. Configure other options as needed
5. Click "Launch"
6. The demo app will handle the authorization flow automatically

**Optional:** Specify authentication type by appending `auth_type` parameter:
- `http://localhost:4567/launch?auth_type=public` - Public client (default)
- `http://localhost:4567/launch?auth_type=confidential_symmetric` - Confidential client with Basic Auth

### Token Refresh

After completing an authorization flow, if the server issued a refresh token:

1. Navigate to the server detail page
2. Click "Test Token Refresh"
3. View the refreshed tokens

## File Structure

```
examples/sinatra_app/
├── app.rb              # Main Sinatra application
├── config.ru           # Rack configuration
├── Gemfile             # Demo app dependencies
├── data/
│   └── servers.yml     # Server configurations (YAML storage)
├── models/
│   └── fhir_server.rb  # Server model with YAML persistence
├── public/
│   └── css/
│       └── style.css   # Application styles
└── views/              # ERB templates
    ├── layout.erb
    ├── index.erb
    ├── servers/
    │   ├── show.erb
    │   ├── new.erb
    │   └── edit.erb
    └── demo/
        ├── discovery.erb
        ├── authorize.erb
        ├── tokens.erb
        └── refresh.erb
```

## License

Apache 2.0
