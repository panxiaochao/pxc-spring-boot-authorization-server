package io.github.panxiaochao.authorization.server.core.authorization.oidc;

import io.github.panxiaochao.authorization.server.core.oidc.OidcUserDetail;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthenticationContext;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>
 * An {@link OAuth2AuthenticationContext} that holds an
 * {@link OidcUserDetailAuthenticationToken} and additional information and is used when
 * mapping claims to an instance of {@link OidcUserDetail}.
 * </p>
 *
 * @author Lypxc
 * @since 2024-03-28
 * @version 1.0
 */
public class OidcUserDetailAuthenticationContext implements OAuth2AuthenticationContext {

	private final Map<Object, Object> context;

	private OidcUserDetailAuthenticationContext(Map<Object, Object> context) {
		this.context = Collections.unmodifiableMap(new HashMap<>(context));
	}

	@SuppressWarnings("unchecked")
	@Nullable
	@Override
	public <V> V get(Object key) {
		return hasKey(key) ? (V) this.context.get(key) : null;
	}

	@Override
	public boolean hasKey(Object key) {
		Assert.notNull(key, "key cannot be null");
		return this.context.containsKey(key);
	}

	/**
	 * Returns the {@link OAuth2AccessToken OAuth 2.0 Access Token}.
	 * @return the {@link OAuth2AccessToken}
	 */
	public OAuth2AccessToken getAccessToken() {
		return get(OAuth2AccessToken.class);
	}

	/**
	 * Returns the {@link OAuth2Authorization authorization}.
	 * @return the {@link OAuth2Authorization}
	 */
	public OAuth2Authorization getAuthorization() {
		return get(OAuth2Authorization.class);
	}

	/**
	 * Constructs a new {@link Builder} with the provided
	 * {@link OidcUserDetailAuthenticationToken}.
	 * @param authentication the {@link OidcUserDetailAuthenticationToken}
	 * @return the {@link Builder}
	 */
	public static Builder with(OidcUserDetailAuthenticationToken authentication) {
		return new Builder(authentication);
	}

	/**
	 * A builder for {@link OidcUserDetailAuthenticationContext}.
	 */
	public static final class Builder extends AbstractBuilder<OidcUserDetailAuthenticationContext, Builder> {

		private Builder(OidcUserDetailAuthenticationToken authentication) {
			super(authentication);
		}

		/**
		 * Sets the {@link OAuth2AccessToken OAuth 2.0 Access Token}.
		 * @param accessToken the {@link OAuth2AccessToken}
		 * @return the {@link Builder} for further configuration
		 */
		public Builder accessToken(OAuth2AccessToken accessToken) {
			return put(OAuth2AccessToken.class, accessToken);
		}

		/**
		 * Sets the {@link OAuth2Authorization authorization}.
		 * @param authorization the {@link OAuth2Authorization}
		 * @return the {@link Builder} for further configuration
		 */
		public Builder authorization(OAuth2Authorization authorization) {
			return put(OAuth2Authorization.class, authorization);
		}

		/**
		 * Builds a new {@link OidcUserDetailAuthenticationContext}.
		 * @return the {@link OidcUserDetailAuthenticationContext}
		 */
		@Override
		public OidcUserDetailAuthenticationContext build() {
			Assert.notNull(get(OAuth2AccessToken.class), "accessToken cannot be null");
			Assert.notNull(get(OAuth2Authorization.class), "authorization cannot be null");
			return new OidcUserDetailAuthenticationContext(getContext());
		}

	}

}
