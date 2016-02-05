export default function OAuthConfig($authProvider) {
    $authProvider.github({
      clientId: '6151497cc320dd5543ec',
      redirectUri: 'http://localhost:8080/src/callback',
      url: 'http://localhost:8080/src/auth/callback'
    });
}