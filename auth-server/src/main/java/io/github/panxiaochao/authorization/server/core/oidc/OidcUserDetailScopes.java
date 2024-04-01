package io.github.panxiaochao.authorization.server.core.oidc;

import org.springframework.security.oauth2.core.oidc.OidcScopes;

/**
 * <p>
 * The scope values defined by the OpenID Connect Core 1.0 specification that can be used
 * to request {@link OidcUserDetailStandardClaimNames claims}.
 * </p>
 *
 * @author Lypxc
 * @since 2024-03-29
 * @version 1.0
 */
public interface OidcUserDetailScopes extends OidcScopes {

	/**
	 * The {@code username} scope requests access to the {@code username} claim.
	 */
	String USERNAME = "username";

	/**
	 * The {@code roles} scope requests access to the {@code roles} claim.
	 */
	String ROLES = "roles";

	/**
	 * The {@code union_id} scope requests access to the {@code union_id} claim.
	 */
	String UNION_ID = "union_id";

	/**
	 * The {@code tenant_id} scope requests access to the {@code tenant_id} claim.
	 */
	String TENANT_ID = "tenant_id";

}
