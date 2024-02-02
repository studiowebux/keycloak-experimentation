import { Issuer } from 'openid-client';

const {
  KEYCLOAK_ISSUER,
  KEYCLOAK_CLIENT_ID,
  KEYCLOAK_CLIENT_SECRET,
  KEYCLOAK_REDIRECT_URIS,
  KEYCLOAK_LOGOUT_REDIRECT_URIS,
  KEYCLOAK_RESPONSE_TYPES,
  KEYCLOAK_BASE_URL,
  KEYCLOAK_REALM,
  KEYCLOAK_RESPONSE_MODE
} = process.env;

const keycloakIssuer = await Issuer.discover(KEYCLOAK_ISSUER);

export const client = new keycloakIssuer.Client({
  client_id: KEYCLOAK_CLIENT_ID,
  client_secret: KEYCLOAK_CLIENT_SECRET,
  redirect_uris: KEYCLOAK_REDIRECT_URIS.split(','),
  post_logout_redirect_uris: KEYCLOAK_LOGOUT_REDIRECT_URIS.split(','),
  response_types: KEYCLOAK_RESPONSE_TYPES.split(',')
});

const isHtmx = (req) => req.headers['hx-request'] === 'true';

export function checkPermission(uri) {
  return async (req, res, next) => {
    // console.debug('CHECK PERMISSION', req.user.token.access_token);
    const response = await fetch(
      `${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded',
          Authorization: `Bearer ${req.user.token.access_token}`
        },
        body: new URLSearchParams({
          grant_type: 'urn:ietf:params:oauth:grant-type:uma-ticket',
          audience: KEYCLOAK_CLIENT_ID,
          response_mode: KEYCLOAK_RESPONSE_MODE,
          permission: uri,
          permission_resource_format: 'uri',
          permission_resource_matching_uri: true
        })
      }
    ).then((res) => res.json());

    // console.log(req.headers);
    console.log(req.session.id)
    console.log(
      'token',
      req.user.token.access_token.substring(req.user.token.access_token - 4)
    );
    console.debug('RESPONSE', response);
    if (KEYCLOAK_RESPONSE_MODE === 'decision') {
      if (response.result) {
        return next();
      }
    } else if (KEYCLOAK_RESPONSE_MODE === 'permissions') {
      if (!response.error) return next();
    }

    return notAuthorized(res, isHtmx(req), req.isAuthenticated());
  };
}

export function checkGroup(group) {
  return async (req, res, next) => {
    // console.debug('CHECK GROUP', req.user.userinfo.groups);
    if (req.user.userinfo.groups.includes(group)) return next();

    return notAuthorized(res, isHtmx(req), req.isAuthenticated());
  };
}

export async function refreshToken(refreshToken) {
  console.debug('REFRESH TOKEN');
  const response = await fetch(
    `${KEYCLOAK_BASE_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token`,
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: KEYCLOAK_CLIENT_ID,
        refresh_token: refreshToken,
        client_secret: KEYCLOAK_CLIENT_SECRET
      })
    }
  ).then((res) => res.json());

  console.debug('Refresh response: ', response);

  return response;
}

function notAuthorized(res, htmx = false, isAuthenticated) {
  return res.render(`${htmx ? 'sections' : 'pages'}/not-authorized`, {
    isAuthenticated,
    error_description: 'Not authorized to access the resource'
  });
}
