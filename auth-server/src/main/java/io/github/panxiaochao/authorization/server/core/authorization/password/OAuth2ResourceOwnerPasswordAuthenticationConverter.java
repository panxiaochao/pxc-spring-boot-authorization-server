package io.github.panxiaochao.authorization.server.core.authorization.password;

import io.github.panxiaochao.security.core.endpoint.OAuth2EndpointUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.*;

/**
 * <p>
 * Attempts to extract an Access Token Request from {@link HttpServletRequest} for the
 * OAuth 2.0 Password Grant and then converts it to an
 * {@link OAuth2ResourceOwnerPasswordAuthenticationConverter} used for authenticating the
 * authorization grant.
 * </p>
 *
 * @author Lypxc
 * @since 2022-12-14
 */
public final class OAuth2ResourceOwnerPasswordAuthenticationConverter implements AuthenticationConverter {

	@Override
	public Authentication convert(HttpServletRequest request) {
		// grant_type (REQUIRED)
		String grantType = request.getParameter(OAuth2ParameterNames.GRANT_TYPE);
		if (!AuthorizationGrantType.PASSWORD.getValue().equals(grantType)) {
			return null;
		}

		MultiValueMap<String, String> parameters = OAuth2EndpointUtils.getParameters(request);

		// scope (OPTIONAL)
		String scope = parameters.getFirst(OAuth2ParameterNames.SCOPE);
		if (StringUtils.hasText(scope) && parameters.get(OAuth2ParameterNames.SCOPE).size() != 1) {
			OAuth2EndpointUtils.throwErrorByParameter(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.SCOPE,
					OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
		}
		Set<String> requestedScopes = null;
		if (StringUtils.hasText(scope)) {
			requestedScopes = new HashSet<>(Arrays.asList(StringUtils.delimitedListToStringArray(scope, " ")));
		}

		// username (REQUIRED)
		String username = parameters.getFirst(OAuth2ParameterNames.USERNAME);
		if (!StringUtils.hasText(username) || parameters.get(OAuth2ParameterNames.USERNAME).size() != 1) {
			OAuth2EndpointUtils.throwErrorByParameter(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.USERNAME,
					OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
		}

		// password (REQUIRED)
		String password = parameters.getFirst(OAuth2ParameterNames.PASSWORD);
		if (!StringUtils.hasText(password) || parameters.get(OAuth2ParameterNames.PASSWORD).size() != 1) {
			OAuth2EndpointUtils.throwErrorByParameter(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ParameterNames.PASSWORD,
					OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
		}

		Authentication clientPrincipal = SecurityContextHolder.getContext().getAuthentication();
		if (clientPrincipal == null) {
			OAuth2EndpointUtils.throwErrorByParameter(OAuth2ErrorCodes.INVALID_REQUEST, OAuth2ErrorCodes.INVALID_CLIENT,
					OAuth2EndpointUtils.ACCESS_TOKEN_REQUEST_ERROR_URI);
		}

		Map<String, Object> additionalParameters = new HashMap<>();
		parameters.forEach((key, value) -> {
			// EXCLUDE PARAMETERS
			if (!key.equals(OAuth2ParameterNames.GRANT_TYPE) && !key.equals(OAuth2ParameterNames.REFRESH_TOKEN)
					&& !key.equals(OAuth2ParameterNames.SCOPE)) {
				additionalParameters.put(key, value.get(0));
			}
		});

		return new OAuth2ResourceOwnerPasswordAuthenticationToken(AuthorizationGrantType.PASSWORD, clientPrincipal,
				requestedScopes, additionalParameters);
	}

}
