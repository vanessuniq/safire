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
- **Authentication Types**:
  - Public Client (PKCE only)
  - Confidential Symmetric (client_secret with Basic Auth)
  - Confidential Asymmetric (private_key_jwt with JWT assertion)
- **Token Management**: View obtained tokens and test token refresh functionality
- **JWKS Endpoint**: Serves the app's public key at `/.well-known/jwks.json` for asymmetric auth

## Quick Start

From the project root:

```bash
bin/demo
```

Or from this directory:

```bash
cp .env.example .env
# Edit .env with your settings
bundle install
bundle exec puma config.ru -p 4567
```

Then visit http://localhost:4567

## Configuration

### Environment Variables

Copy `.env.example` to `.env` and configure:

| Variable | Required | Description |
|----------|----------|-------------|
| `PORT` | No | Server port (default: 4567) |
| `SESSION_SECRET` | No | Session encryption key (auto-generated if not set) |
| `ASYMMETRIC_PRIVATE_KEY_PEM` | No | Private key in PEM format for asymmetric auth |
| `ASYMMETRIC_KID` | No | Key ID matching your registered JWKS |

### Setting Up Asymmetric Authentication

Asymmetric authentication uses JWT assertions signed with a private key. This is more secure than shared secrets.

1. **Generate a key pair** (RSA or EC):
   ```bash
   # RSA (recommended)
   openssl genrsa -out private_key.pem 2048

   # EC P-384
   openssl ecparam -name secp384r1 -genkey -noout -out private_key.pem
   ```

2. **Configure environment variables**:
   ```bash
   # In .env file
   ASYMMETRIC_PRIVATE_KEY_PEM="-----BEGIN PRIVATE KEY-----
   ...your key content...
   -----END PRIVATE KEY-----"

   ASYMMETRIC_KID=my-app-key-001
   ```

3. **Register with the authorization server**:
   - Provide your JWKS URL: `http://localhost:4567/.well-known/jwks.json`
   - Or extract and upload your public key:
     ```bash
     openssl rsa -in private_key.pem -pubout -out public_key.pem
     ```

4. **Test**: The "Confidential Asymmetric" option will appear in the authorization form when the server supports it.

### Adding a FHIR Server

1. Click "Add Server" on the home page
2. Enter the server details:
   - **Name**: Display name for the server
   - **Base URL**: FHIR server base URL
   - **Client ID**: OAuth client ID registered with the server
   - **Client Secret**: (Optional) For confidential symmetric clients only
   - **Scopes**: Space or comma-separated list of OAuth scopes

## Demo Workflows

### Testing with SMART Health IT Sandbox

The app works with the SMART Health IT sandbox server for testing.

#### Standalone Launch

1. Select a server from the server list
2. Click "Start Authorization"
3. Choose your settings:
   - **Launch Type**: Provider Standalone or Patient Standalone
   - **Auth Type**: Public, Confidential Symmetric, or Confidential Asymmetric
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
- `http://localhost:4567/launch?auth_type=confidential_asymmetric` - Confidential client with JWT assertion

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
├── .env.example        # Environment variable template
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

## Endpoints

| Path | Description |
|------|-------------|
| `/.well-known/jwks.json` | JWKS endpoint serving the app's public key |
| `/launch` | EHR/Portal launch endpoint |
| `/callback` | OAuth2 callback handler |

## License

Apache 2.0
