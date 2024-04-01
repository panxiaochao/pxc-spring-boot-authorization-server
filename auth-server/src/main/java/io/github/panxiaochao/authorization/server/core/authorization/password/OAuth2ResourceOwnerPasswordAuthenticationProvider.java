package io.github.panxiaochao.authorization.server.core.authorization.password;

import io.github.panxiaochao.security.core.endpoint.OAuth2EndpointUtils;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClaimAccessor;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.DefaultOAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.security.Principal;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * <p>
 * An AuthenticationProvider implementation for the OAuth 2.0 Password Grant.
 * </p>
 *
 * @author Lypxc
 * @since 2022-12-14
 */
@Getter
public final class OAuth2ResourceOwnerPasswordAuthenticationProvider implements AuthenticationProvider {

	private static final Logger LOGGER = LoggerFactory
		.getLogger(OAuth2ResourceOwnerPasswordAuthenticationProvider.class);

	private static final String ERROR_URI = "https://datatracker.ietf.org/doc/html/rfc6749#section-5.2";

	private static final OAuth2TokenType ID_TOKEN_TOKEN_TYPE = new OAuth2TokenType(OidcParameterNames.ID_TOKEN);

	private final OAuth2AuthorizationService authorizationService;

	private final OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator;

	private final AuthenticationManager authenticationManager;

	public OAuth2ResourceOwnerPasswordAuthenticationProvider(AuthenticationManager authenticationManager,
			OAuth2AuthorizationService authorizationService,
			OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator) {
		Assert.notNull(authorizationService, "authorizationService cannot be null");
		Assert.notNull(tokenGenerator, "tokenGenerator cannot be null");
		Assert.notNull(authenticationManager, "authenticationManager cannot be null");
		this.authenticationManager = authenticationManager;
		this.authorizationService = authorizationService;
		this.tokenGenerator = tokenGenerator;
	}

	/**
	 * @param authentication the authentication request object.
	 * @return Authentication
	 * @throws AuthenticationException throws authenticationException
	 */
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		OAuth2ResourceOwnerPasswordAuthenticationToken resourceOwnerPasswordAuthenticationToken = (OAuth2ResourceOwnerPasswordAuthenticationToken) authentication;
		Set<String> requestedScopes = resourceOwnerPasswordAuthenticationToken.getScopes();
		//
		OAuth2ClientAuthenticationToken clientPrincipal = getAuthenticatedClientElseThrowInvalidClient(
				resourceOwnerPasswordAuthenticationToken);
		RegisteredClient registeredClient = clientPrincipal.getRegisteredClient();
		if (Objects.isNull(registeredClient)) {
			OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.SERVER_ERROR, "The RegisteredClient is null.", null);
		}
		else if (!registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.PASSWORD)) {
			OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_GRANT, "The Invalid Grant.", null);
		}
		Authentication principal = authenticate(resourceOwnerPasswordAuthenticationToken);
		Set<String> authorizedScopes = Collections.emptySet();
		if (!CollectionUtils.isEmpty(requestedScopes)) {
			for (String requestedScope : requestedScopes) {
				if (Objects.nonNull(registeredClient.getScopes())
						&& !registeredClient.getScopes().contains(requestedScope)) {
					OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.INVALID_SCOPE, "The Invalid Scope.", null);
				}
			}
			authorizedScopes = new LinkedHashSet<>(requestedScopes);
		}
		// OAuth2Authorization
		OAuth2Authorization authorization = OAuth2Authorization.withRegisteredClient(registeredClient)
			.principalName(clientPrincipal.getName())
			.authorizationGrantType(AuthorizationGrantType.PASSWORD)
			.authorizedScopes(authorizedScopes)
			.attributes(attributesConsumer -> attributesConsumer.put(Principal.class.getName(), principal))
			.build();
		// DefaultOAuth2TokenContext.Builder
		DefaultOAuth2TokenContext.Builder tokenContextBuilder = DefaultOAuth2TokenContext.builder()
			.registeredClient(registeredClient)
			.principal(authorization.getAttribute(Principal.class.getName()))
			.authorizationServerContext(AuthorizationServerContextHolder.getContext())
			.authorization(authorization)
			.authorizedScopes(authorizedScopes)
			.authorizationGrantType(AuthorizationGrantType.PASSWORD)
			.authorizationGrant(resourceOwnerPasswordAuthenticationToken);
		// OAuth2Authorization.Builder
		OAuth2Authorization.Builder authorizationBuilder = OAuth2Authorization.from(authorization);
		// Access token
		OAuth2AccessToken accessToken = generateAccessToken(tokenContextBuilder, authorizationBuilder);
		// Refresh token
		OAuth2RefreshToken oauth2RefreshToken = generateRefreshToken(registeredClient, clientPrincipal,
				tokenContextBuilder, authorizationBuilder);
		// ID token
		Map<String, Object> additionalParameters = Collections.emptyMap();
		if (requestedScopes.contains(OidcScopes.OPENID)) {
			OidcIdToken idToken = generateOidcIdToken(tokenContextBuilder, authorizationBuilder);
			if (Objects.nonNull(idToken)) {
				additionalParameters = new HashMap<>();
				additionalParameters.put(OidcParameterNames.ID_TOKEN, idToken.getTokenValue());
			}
		}
		// OAuth2Authorization
		authorization = authorizationBuilder.build();
		authorizationService.save(authorization);
		LOGGER.info("Saved authorization");
		return new OAuth2AccessTokenAuthenticationToken(registeredClient, clientPrincipal, accessToken,
				oauth2RefreshToken, additionalParameters);
	}

	private OAuth2AccessToken generateAccessToken(DefaultOAuth2TokenContext.Builder tokenContextBuilder,
			OAuth2Authorization.Builder authorizationBuilder) {
		OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.ACCESS_TOKEN).build();
		OAuth2Token generatedAccessToken = tokenGenerator.generate(tokenContext);
		if (generatedAccessToken == null) {
			OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.SERVER_ERROR,
					"The token generator failed to generate the access token.", ERROR_URI);
		}
		OAuth2AccessToken accessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER,
				generatedAccessToken.getTokenValue(), generatedAccessToken.getIssuedAt(),
				generatedAccessToken.getExpiresAt(), tokenContext.getAuthorizedScopes());
		if (generatedAccessToken instanceof ClaimAccessor) {
			authorizationBuilder.token(accessToken,
					(metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME,
							((ClaimAccessor) generatedAccessToken).getClaims()));
		}
		else {
			authorizationBuilder.accessToken(accessToken);
		}
		return accessToken;
	}

	private OAuth2RefreshToken generateRefreshToken(RegisteredClient registeredClient,
			OAuth2ClientAuthenticationToken clientPrincipal, DefaultOAuth2TokenContext.Builder tokenContextBuilder,
			OAuth2Authorization.Builder authorizationBuilder) {
		OAuth2RefreshToken oauth2RefreshToken = null;
		if (registeredClient.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)
				&& !clientPrincipal.getClientAuthenticationMethod().equals(ClientAuthenticationMethod.NONE)) {
			OAuth2TokenContext tokenContext = tokenContextBuilder.tokenType(OAuth2TokenType.REFRESH_TOKEN).build();
			OAuth2Token generatedRefreshToken = tokenGenerator.generate(tokenContext);
			if (!(generatedRefreshToken instanceof OAuth2RefreshToken)) {
				OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.SERVER_ERROR,
						"The token generator failed to generate the refresh token.", ERROR_URI);
			}
			oauth2RefreshToken = (OAuth2RefreshToken) generatedRefreshToken;
			authorizationBuilder.refreshToken(oauth2RefreshToken);
		}
		return oauth2RefreshToken;
	}

	private Authentication authenticate(
			OAuth2ResourceOwnerPasswordAuthenticationToken resourceOwnerPasswordAuthenticationToken) {
		Map<String, Object> requestAdditionalParameters = resourceOwnerPasswordAuthenticationToken
			.getAdditionalParameters();
		String username = requestAdditionalParameters.get(OAuth2ParameterNames.USERNAME).toString();
		String password = requestAdditionalParameters.get(OAuth2ParameterNames.PASSWORD).toString();
		UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(
				username, password);
		return authenticationManager.authenticate(usernamePasswordAuthenticationToken);
	}

	private OidcIdToken generateOidcIdToken(DefaultOAuth2TokenContext.Builder tokenContextBuilder,
			OAuth2Authorization.Builder authorizationBuilder) {
		// @formatter:off
		OAuth2TokenContext tokenContext = tokenContextBuilder
				.tokenType(ID_TOKEN_TOKEN_TYPE)
				.authorization(authorizationBuilder.build())
				.build();
		// @formatter:on
		OAuth2Token generatedIdToken = tokenGenerator.generate(tokenContext);
		if (!(generatedIdToken instanceof Jwt)) {
			OAuth2EndpointUtils.throwError(OAuth2ErrorCodes.SERVER_ERROR,
					"The token generator failed to generate the ID token.", ERROR_URI);
		}
		LOGGER.info("Generated id token");
		OidcIdToken idToken = new OidcIdToken(generatedIdToken.getTokenValue(), generatedIdToken.getIssuedAt(),
				generatedIdToken.getExpiresAt(), ((Jwt) generatedIdToken).getClaims());
		if (Objects.nonNull(idToken)) {
			authorizationBuilder.token(idToken,
					(metadata) -> metadata.put(OAuth2Authorization.Token.CLAIMS_METADATA_NAME, idToken.getClaims()));
		}
		return idToken;
	}

	private OAuth2ClientAuthenticationToken getAuthenticatedClientElseThrowInvalidClient(
			Authentication authentication) {
		OAuth2ClientAuthenticationToken clientPrincipal = null;
		if (OAuth2ClientAuthenticationToken.class.isAssignableFrom(authentication.getPrincipal().getClass())) {
			clientPrincipal = (OAuth2ClientAuthenticationToken) authentication.getPrincipal();
		}
		if (clientPrincipal != null && clientPrincipal.isAuthenticated()) {
			return clientPrincipal;
		}
		throw new OAuth2AuthenticationException(OAuth2ErrorCodes.INVALID_CLIENT);
	}

	// private UserDetailsService userDetailsService() {
	// return SpringContextUtil.getBean(UserDetailsServiceImpl.class);
	// }

	// private PasswordEncoder passwordEncoder() {
	// return SpringContextUtil.getBean(PasswordEncoder.class);
	// }

	// private OAuth2AuthorizationService authorizationService() {
	// return SpringContextUtil.getBean(OAuth2AuthorizationService.class);
	// }

	// private OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator() {
	// return (OAuth2TokenGenerator<? extends OAuth2Token>)
	// SpringContextUtil.getBean(OAuth2TokenGenerator.class);
	// }

	@Override
	public boolean supports(Class<?> authentication) {
		return OAuth2ResourceOwnerPasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}

}
