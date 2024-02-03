import { Issuer, custom } from 'openid-client';
import { isHtmx } from './helpers.js';

const {
  KEYCLOAK_ISSUER,
  KEYCLOAK_CLIENT_ID,
  KEYCLOAK_CLIENT_SECRET,
  KEYCLOAK_REDIRECT_URIS,
  KEYCLOAK_LOGOUT_REDIRECT_URIS,
  KEYCLOAK_RESPONSE_TYPES,
  KEYCLOAK_RESPONSE_MODE
} = process.env;

// Fetch issuer information from Keycloak
const issuer = await Issuer.discover(KEYCLOAK_ISSUER);

// Setup Keycloak client using openid-client
export const client = new issuer.Client({
  client_id: KEYCLOAK_CLIENT_ID,
  client_secret: KEYCLOAK_CLIENT_SECRET,
  redirect_uris: KEYCLOAK_REDIRECT_URIS.split(','),
  post_logout_redirect_uris: KEYCLOAK_LOGOUT_REDIRECT_URIS.split(','),
  response_types: KEYCLOAK_RESPONSE_TYPES.split(',')
});

// Hook to inject the access token, keycloak is different.
// https://github.com/panva/node-openid-client/tree/main/docs#customizing-individual-http-requests
// https://github.com/panva/node-openid-client/issues/211#issuecomment-558210891
client[custom.http_options] = (url, options) => {
  if (
    url.href === issuer.token_endpoint &&
    options.form.access_token &&
    options.form.grant_type === 'urn:ietf:params:oauth:grant-type:uma-ticket'
  ) {
    const { access_token } = options.form;
    delete options.form.access_token;
    options.headers = options.headers || {};
    options.headers.Authorization = `Bearer ${access_token}`;
  }
  return options;
};

/**
 * Check Permission from the Authorization Server (AS)
 * It supports multiple format:
 * resource uri: `/uri/*` or `/uri/abc` and so on..
 * resource uri + scope: `/uri/*#create,view` or `/uri/abc#view` and so on..
 * @param {String} uri 
 * @returns next() or not authorized
 */
export function checkPermission(uri) {
  return async (req, res, next) => {
    try {
      const response = await client.grant({
        grant_type: 'urn:ietf:params:oauth:grant-type:uma-ticket',
        audience: KEYCLOAK_CLIENT_ID,
        response_mode: KEYCLOAK_RESPONSE_MODE,
        permission: uri,
        permission_resource_format: 'uri',
        permission_resource_matching_uri: true,
        access_token: req.user.token.access_token
      });

      if (KEYCLOAK_RESPONSE_MODE === 'decision') {
        if (response.result === true) {
          return next();
        }
      } else if (KEYCLOAK_RESPONSE_MODE === 'permissions') {
        if (!response.error) return next();
      }

      return notAuthorized(res, isHtmx(req), req.isAuthenticated());
    } catch {
      return notAuthorized(res, isHtmx(req), req.isAuthenticated());
    }
  };
}

/**
 * Check in the user group claim if the required group is present
 * @param {String} group Required group to access the resource
 * @returns next() or not authorized
 */
export function checkGroup(group) {
  return async (req, res, next) => {
    if (req.user.userinfo.groups.includes(group)) return next();

    return notAuthorized(res, isHtmx(req), req.isAuthenticated());
  };
}

/**
 * Renders a not authorized section or a page
 * @param {object} res 
 * @param {boolean} htmx for the render function
 * @param {boolean} isAuthenticated for the render function
 * @returns 
 */
function notAuthorized(res, htmx = false, isAuthenticated) {
  return res.render(`${htmx ? 'sections' : 'pages'}/not-authorized`, {
    isAuthenticated,
    error_description: 'Not authorized to access the resource'
  });
}
