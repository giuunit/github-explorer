export default function OAuthConfig($authProvider) {
    $authProvider.github({
      clientId: '6151497cc320dd5543ec',
      redirectUri: window.location.origin + '/callback'
    });
}