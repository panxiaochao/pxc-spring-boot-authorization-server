package io.github.panxiaochao.authorization.server.core.authorization.password;

import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;

import java.util.*;

/**
 * <p>
 * An Object implementation used for password gant an OAuth 2.0 Access Token
 * </p>
 *
 * @author Lypxc
 * @since 2022-12-14
 */
@Getter
public final class OAuth2ResourceOwnerPasswordAuthenticationToken extends AbstractAuthenticationToken {

	private static final Logger LOGGER = LoggerFactory.getLogger(OAuth2ResourceOwnerPasswordAuthenticationToken.class);

	private final AuthorizationGrantType authorizationGrantType;

	private final Object clientPrincipal;

	private final Set<String> scopes;

	private final Map<String, Object> additionalParameters;

	/**
	 * <p>
	 * 自定义创建Token
	 * </p>
	 */
	public OAuth2ResourceOwnerPasswordAuthenticationToken(Collection<? extends GrantedAuthority> authorities,
			AuthorizationGrantType authorizationGrantType, Object clientPrincipal, Set<String> scopes,
			Map<String, Object> additionalParameters) {
		super(authorities);
		Assert.notNull(authorizationGrantType, "authorizationGrantType cannot be null");
		Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
		this.authorizationGrantType = authorizationGrantType;
		this.clientPrincipal = clientPrincipal;
		this.scopes = Collections.unmodifiableSet(scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
		this.additionalParameters = Collections.unmodifiableMap(
				additionalParameters != null ? new HashMap<>(additionalParameters) : Collections.emptyMap());
		super.setAuthenticated(true);
	}

	public OAuth2ResourceOwnerPasswordAuthenticationToken(AuthorizationGrantType authorizationGrantType,
			Object clientPrincipal, Set<String> scopes, Map<String, Object> additionalParameters) {
		super(Collections.emptyList());
		Assert.notNull(authorizationGrantType, "authorizationGrantType cannot be null");
		Assert.notNull(clientPrincipal, "clientPrincipal cannot be null");
		this.authorizationGrantType = authorizationGrantType;
		this.clientPrincipal = clientPrincipal;
		this.scopes = Collections.unmodifiableSet(scopes != null ? new HashSet<>(scopes) : Collections.emptySet());
		this.additionalParameters = Collections.unmodifiableMap(
				additionalParameters != null ? new HashMap<>(additionalParameters) : Collections.emptyMap());
		this.setAuthenticated(false);
	}

	@Override
	public Object getPrincipal() {
		return this.clientPrincipal;
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
		if (isAuthenticated) {
			throw new IllegalArgumentException(
					"Cannot set this token to trusted - use constructor which takes a GrantedAuthority list instead");
		}
		else {
			super.setAuthenticated(false);
		}
	}

}
