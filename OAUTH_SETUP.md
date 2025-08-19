# OAuth Provider Setup Guide

This guide explains how to configure OAuth providers (Google and GitHub) for the authentication demo application.

## Environment Variables

Add the following environment variables to your `.env` file or environment:

```bash
# Google OAuth
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret

# GitHub OAuth
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret
```

## Google OAuth Setup

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Google+ API
4. Go to "Credentials" → "Create Credentials" → "OAuth 2.0 Client IDs"
5. Choose "Web application" as the application type
6. Add authorized redirect URIs:
   - `http://localhost:8000/oauth/google/callback` (for local development)
   - `https://yourdomain.com/oauth/google/callback` (for production)
7. Copy the Client ID and Client Secret to your environment variables

## GitHub OAuth Setup

1. Go to [GitHub Settings](https://github.com/settings/developers)
2. Click "New OAuth App"
3. Fill in the application details:
   - Application name: Your app name
   - Homepage URL: Your app URL
   - Authorization callback URL: 
     - `http://localhost:8000/oauth/github/callback` (for local development)
     - `https://yourdomain.com/oauth/github/callback` (for production)
4. Click "Register application"
5. Copy the Client ID and Client Secret to your environment variables

## Database Setup

Run the OAuth database migration:

```bash
# Connect to your PostgreSQL database
psql -U auth_user -d auth_demo

# Run the OAuth migration
\i init/02-oauth-support.sql
```

## Testing OAuth

1. Start the application with the environment variables set
2. Go to the login or registration page
3. Click on "Continue with Google" or "Continue with GitHub"
4. Complete the OAuth flow
5. You should be redirected back and logged in

## Security Notes

- Never commit OAuth client secrets to version control
- Use environment variables or secure configuration management
- Set appropriate redirect URIs to prevent unauthorized redirects
- Consider implementing CSRF protection for OAuth flows
- Regularly rotate OAuth client secrets

## Troubleshooting

### Common Issues

1. **"Provider not found or inactive"**: Check that the OAuth provider is properly configured in the database
2. **"Invalid redirect URI"**: Ensure the redirect URI in your OAuth app matches exactly
3. **"Token exchange failed"**: Verify your client ID and secret are correct
4. **"Connection error"**: Check that the backend is running and accessible

### Debug Mode

Enable debug logging in the backend to see detailed OAuth flow information:

```python
app.config['DEBUG'] = True
```

## OAuth Flow Diagram

```
User → Frontend → Backend → OAuth Provider
  ↑                                    ↓
  ← Frontend ← Backend ← OAuth Provider
```

1. User clicks OAuth login button
2. Frontend requests authorization URL from backend
3. Backend redirects to OAuth provider
4. User authenticates with OAuth provider
5. OAuth provider redirects back to frontend callback
6. Frontend exchanges code for token via backend
7. Backend creates/updates user and returns JWT
8. User is logged in
