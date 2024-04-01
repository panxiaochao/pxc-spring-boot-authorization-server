package io.github.panxiaochao.authorization.server.core.authorization.oidc;

import io.github.panxiaochao.authorization.server.core.oidc.OidcUserDetail;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

import java.util.Collections;

/**
 * <p>
 * An {@link Authentication} implementation used for OpenID Connect 1.0 OidcUserDetail
 * Endpoint.
 * </p>
 *
 * @author Lypxc
 * @since 2024-03-28
 * @version 1.0
 */
public class OidcUserDetailAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = 1L;

	private final Authentication principal;

	private final OidcUserDetail userInfo;

	/**
	 * Constructs an {@code OidcUserDetailAuthenticationToken} using the provided
	 * parameters.
	 * @param principal the principal
	 */
	public OidcUserDetailAuthenticationToken(Authentication principal) {
		super(Collections.emptyList());
		Assert.notNull(principal, "principal cannot be null");
		this.principal = principal;
		this.userInfo = null;
		setAuthenticated(false);
	}

	/**
	 * Constructs an {@code OidcUserDetailAuthenticationToken} using the provided
	 * parameters.
	 * @param principal the authenticated principal
	 * @param userInfo the OidcUserDetail claims
	 */
	public OidcUserDetailAuthenticationToken(Authentication principal, OidcUserDetail userInfo) {
		super(Collections.emptyList());
		Assert.notNull(principal, "principal cannot be null");
		Assert.notNull(userInfo, "userInfo cannot be null");
		this.principal = principal;
		this.userInfo = userInfo;
		setAuthenticated(true);
	}

	@Override
	public Object getPrincipal() {
		return this.principal;
	}

	@Override
	public Object getCredentials() {
		return "";
	}

	public OidcUserDetail getUserInfo() {
		return this.userInfo;
	}

}
