import { Issuer } from 'openid-client';

const {
  KEYCLOAK_ISSUER,
  KEYCLOAK_CLIENT_ID,
  KEYCLOAK_CLIENT_SECRET,
  KEYCLOAK_REDIRECT_URIS,
  KEYCLOAK_LOGOUT_REDIRECT_URIS,
  KEYCLOAK_RESPONSE_TYPES
} = process.env;

const keycloakIssuer = await Issuer.discover(KEYCLOAK_ISSUER);

export const client = new keycloakIssuer.Client({
  client_id: KEYCLOAK_CLIENT_ID,
  client_secret: KEYCLOAK_CLIENT_SECRET,
  redirect_uris: KEYCLOAK_REDIRECT_URIS.split(','),
  post_logout_redirect_uris: KEYCLOAK_LOGOUT_REDIRECT_URIS.split(','),
  response_types: KEYCLOAK_RESPONSE_TYPES.split(',')
});
