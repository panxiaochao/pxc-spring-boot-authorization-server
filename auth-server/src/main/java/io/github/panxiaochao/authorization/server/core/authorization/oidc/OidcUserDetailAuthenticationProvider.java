package io.github.panxiaochao.authorization.server.core.authorization.oidc;

import io.github.panxiaochao.authorization.server.core.oidc.OidcUserDetail;
import io.github.panxiaochao.authorization.server.core.oidc.OidcUserDetailScopes;
import io.github.panxiaochao.authorization.server.core.oidc.OidcUserDetailStandardClaimNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.util.Assert;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Function;

/**
 * <p>
 * An {@link AuthenticationProvider} implementation for OpenID Connect 1.0 UserInfo
 * Endpoint.
 * </p>
 *
 * @author Lypxc
 * @since 2024-03-28
 * @version 1.0
 */
public class OidcUserDetailAuthenticationProvider implements AuthenticationProvider {

	/**
	 * LOGGER OidcUserDetailAuthenticationProvider.class
	 */
	private static final Logger LOGGER = LoggerFactory.getLogger(OidcUserDetailAuthenticationProvider.class);

	private final OAuth2AuthorizationService authorizationService;

	private Function<OidcUserDetailAuthenticationContext, OidcUserDetail> userInfoMapper = new DefaultOidcUserDetailMapper();

	/**
	 * Constructs an {@code OidcUserDetailAuthenticationProvider} using the provided
	 * parameters.
	 * @param authorizationService the authorization service
	 */
	public OidcUserDetailAuthenticationProvider(OAuth2AuthorizationService authorizationService) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		this.authorizationService = authorizationService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OidcUserDetailAuthenticationToken userInfoAuthentication = (OidcUserDetailAuthenticationToken) authentication;

		AbstractOAuth2TokenAuthenticationToken<?> accessTokenAuthentication = null;
		if (AbstractOAuth2TokenAuthenticationToken.class
			.isAssignableFrom(userInfoAuthentication.getPrincipal().getClass())) {
			accessTokenAuthentication = (AbstractOAuth2TokenAuthenticationToken<?>) userInfoAuthentication
				.getPrincipal();
		}
		if (accessTokenAuthentication == null || !accessTokenAuthentication.isAuthenticated()) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
		}

		String accessTokenValue = accessTokenAuthentication.getToken().getTokenValue();

		OAuth2Authorization authorization = this.authorizationService.findByToken(accessTokenValue,
				OAuth2TokenType.ACCESS_TOKEN);
		if (authorization == null) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
		}

		OAuth2Authorization.Token<OAuth2AccessToken> authorizedAccessToken = authorization.getAccessToken();
		if (!authorizedAccessToken.isActive()) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
		}

		if (!authorizedAccessToken.getToken().getScopes().contains(OidcUserDetailScopes.OPENID)) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INSUFFICIENT_SCOPE);
		}

		OAuth2Authorization.Token<OidcIdToken> idToken = authorization.getToken(OidcIdToken.class);
		if (idToken == null) {
			throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_TOKEN);
		}

		OidcUserDetailAuthenticationContext authenticationContext = OidcUserDetailAuthenticationContext
			.with(userInfoAuthentication)
			.accessToken(authorizedAccessToken.getToken())
			.authorization(authorization)
			.build();
		OidcUserDetail userInfo = this.userInfoMapper.apply(authenticationContext);

		return new OidcUserDetailAuthenticationToken(accessTokenAuthentication, userInfo);
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return OidcUserDetailAuthenticationToken.class.isAssignableFrom(authentication);
	}

	public void setUserInfoMapper(Function<OidcUserDetailAuthenticationContext, OidcUserDetail> userInfoMapper) {
		Assert.notNull(userInfoMapper, "userInfoMapper cannot be null");
		this.userInfoMapper = userInfoMapper;
	}

	private static class DefaultOidcUserDetailMapper
			implements Function<OidcUserDetailAuthenticationContext, OidcUserDetail> {

		// scope: [email]
		private static final List<String> EMAIL_CLAIMS = Arrays.asList(OidcUserDetailStandardClaimNames.EMAIL,
				OidcUserDetailStandardClaimNames.EMAIL_VERIFIED);

		// scope: [phone]
		private static final List<String> PHONE_CLAIMS = Arrays.asList(OidcUserDetailStandardClaimNames.PHONE_NUMBER,
				OidcUserDetailStandardClaimNames.PHONE_NUMBER_VERIFIED);

		// scope: [profile]
		private static final List<String> PROFILE_CLAIMS = Arrays.asList(OidcUserDetailStandardClaimNames.NAME,
				OidcUserDetailStandardClaimNames.FAMILY_NAME, OidcUserDetailStandardClaimNames.GIVEN_NAME,
				OidcUserDetailStandardClaimNames.MIDDLE_NAME, OidcUserDetailStandardClaimNames.NICKNAME,
				OidcUserDetailStandardClaimNames.PREFERRED_USERNAME, OidcUserDetailStandardClaimNames.PROFILE,
				OidcUserDetailStandardClaimNames.PICTURE, OidcUserDetailStandardClaimNames.WEBSITE,
				OidcUserDetailStandardClaimNames.GENDER, OidcUserDetailStandardClaimNames.BIRTHDATE,
				OidcUserDetailStandardClaimNames.ZONEINFO, OidcUserDetailStandardClaimNames.LOCALE,
				OidcUserDetailStandardClaimNames.UPDATED_AT);

		/**
		 * 使用自定义数据Scope, mapping claims to an instance of {@link OidcUserDetail}.
		 */
		@Override
		public OidcUserDetail apply(OidcUserDetailAuthenticationContext authenticationContext) {
			OidcUserDetailAuthenticationToken userInfoAuthentication = authenticationContext.getAuthentication();
			OidcUserDetail oidcUserDetail = userInfoAuthentication.getUserInfo();
			OAuth2AccessToken accessToken = authenticationContext.getAccessToken();
			Map<String, Object> scopeRequestedClaims = getClaimsRequestedByScope(oidcUserDetail.getClaims(),
					accessToken.getScopes());
			return OidcUserDetail.builder().claims(scopeRequestedClaims).build();
		}

		private static Map<String, Object> getClaimsRequestedByScope(Map<String, Object> claims,
				Set<String> requestedScopes) {
			Set<String> scopeRequestedClaimNames = new HashSet<>();
			scopeRequestedClaimNames.add(OidcUserDetailStandardClaimNames.SUB);
			if (requestedScopes.contains(OidcUserDetailScopes.USERNAME)) {
				scopeRequestedClaimNames.add(OidcUserDetailStandardClaimNames.USERNAME);
			}
			if (requestedScopes.contains(OidcUserDetailScopes.ADDRESS)) {
				scopeRequestedClaimNames.add(OidcUserDetailStandardClaimNames.ADDRESS);
			}
			if (requestedScopes.contains(OidcUserDetailScopes.EMAIL)) {
				scopeRequestedClaimNames.addAll(EMAIL_CLAIMS);
			}
			if (requestedScopes.contains(OidcUserDetailScopes.PHONE)) {
				scopeRequestedClaimNames.addAll(PHONE_CLAIMS);
			}
			if (requestedScopes.contains(OidcUserDetailScopes.PROFILE)) {
				scopeRequestedClaimNames.addAll(PROFILE_CLAIMS);
			}
			if (requestedScopes.contains(OidcUserDetailScopes.ROLES)) {
				scopeRequestedClaimNames.add(OidcUserDetailStandardClaimNames.ROLES);
			}
			if (requestedScopes.contains(OidcUserDetailScopes.UNION_ID)) {
				scopeRequestedClaimNames.add(OidcUserDetailStandardClaimNames.UNION_ID);
			}
			if (requestedScopes.contains(OidcUserDetailScopes.TENANT_ID)) {
				scopeRequestedClaimNames.add(OidcUserDetailStandardClaimNames.TENANT_ID);
			}

			Map<String, Object> requestedClaims = new HashMap<>(claims);
			requestedClaims.keySet().removeIf(claimName -> !scopeRequestedClaimNames.contains(claimName));
			return requestedClaims;
		}

	}

}
