package io.github.panxiaochao.authorization.server.endpoint;

import io.github.panxiaochao.authorization.server.core.oidc.OidcUserDetailScopes;
import io.github.panxiaochao.authorization.server.properties.AuthorizationProperties;
import io.github.panxiaochao.core.response.R;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.annotation.Resource;
import java.time.Duration;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;

/**
 * <p>
 * RegisteredClient 初始化接口
 * </p>
 *
 * @author Lypxc
 * @since 2023-07-24
 */
@RestController
@RequestMapping("/api")
public class ApiRegisteredClient {

	@Resource
	private RegisteredClientRepository registeredClientRepository;

	@Resource
	private AuthorizationProperties authorizationProperties;

	@Resource
	private PasswordEncoder passwordEncoder;

	/**
	 * http://127.0.0.1:18000/api/create?grantType=authorization_code&clientId=client_code&secret=123456@
	 */
	@GetMapping("/create")
	public R<String> createRegisteredClient(@RequestParam String grantType, @RequestParam String clientId,
			@RequestParam String secret, @RequestParam(required = false) String redirectUri) {
		if ("password".equals(grantType)) {
			return createRegisteredClient(clientId, secret);
		}
		else if ("authorization_code".equals(grantType)) {
			return createAuthorizationCodeRegisteredClient(clientId, secret, redirectUri);
		}
		else {
			return R.fail(grantType + " is not supported");
		}
	}

	/**
	 * 创建客户端秘钥记录
	 * @return RegisteredClient
	 */
	private R<String> createRegisteredClient(String clientId, String secret) {
		RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
		if (Objects.isNull(registeredClient)) {
			registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId(clientId)
				.clientSecret(passwordEncoder.encode(secret))
				// .clientName(authorizationProperties.getClientServer())
				// 端点的调用模式 client_id:client_secret Base64编码
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.authorizationGrantType(AuthorizationGrantType.PASSWORD)
				.scope(OidcScopes.OPENID)
				.scope("message:read")
				.scope("message:write")
				.tokenSettings(tokenSettings())
				.clientSettings(clientSettings(false))
				.build();
			registeredClientRepository.save(registeredClient);
		}
		else {
			return R.fail(clientId + "已存在！");
		}
		return R.ok();
	}

	/**
	 * <pre>
	 *     http://127.0.0.1:18000/oauth2/v1/authorize?response_type=code&scope=openid profile&client_id=client_code&redirect_uri=https://www.baidu.com
	 *     http://127.0.0.1:18000/oauth2/v1/authorize?response_type=code&scope=openid profile&client_id=client-code-scope&redirect_uri=https://www.baidu.com
	 * </pre>
	 */
	private R<String> createAuthorizationCodeRegisteredClient(String clientId, String secret, String redirectUri) {
		RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
		if (Objects.isNull(registeredClient)) {
			registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId(clientId)
				.clientSecret(passwordEncoder.encode(secret))
				// .clientName("client_code_server")
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				// 回调地址
				// .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
				// .redirectUri("http://127.0.0.1:8080/authorized")
				.redirectUri("https://www.baidu.com")
				.redirectUris(uris -> {
					if (StringUtils.hasText(redirectUri)) {
						String[] redirectUris = redirectUri.split(",");
						uris.addAll(Arrays.asList(redirectUris));
					}
				})
				.scope(OidcUserDetailScopes.OPENID)
				.scope(OidcUserDetailScopes.PROFILE)
				.scope(OidcUserDetailScopes.EMAIL)
				.scope(OidcUserDetailScopes.ADDRESS)
				.scope(OidcUserDetailScopes.PHONE)
				.scope(OidcUserDetailScopes.USERNAME)
				.scope(OidcUserDetailScopes.ROLES)
				.scope(OidcUserDetailScopes.UNION_ID)
				.scope(OidcUserDetailScopes.TENANT_ID)
				.scope("message.read")
				.scope("message.write")
				.tokenSettings(tokenSettings())
				.clientSettings(clientSettings(true))
				.build();
			registeredClientRepository.save(registeredClient);
		}
		else {
			return R.fail(clientId + "已存在！");
		}
		return R.ok();
	}

	/**
	 * JWT（Json Web Token）的配置项：TTL、是否复用refreshToken等等
	 * @return TokenSettings
	 */
	public TokenSettings tokenSettings() {
		return TokenSettings.builder()
			.accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
			.reuseRefreshTokens(true)
			.accessTokenTimeToLive(Duration.ofSeconds(3600))
			.refreshTokenTimeToLive(Duration.ofSeconds(7200))
			.idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
			.build();
	}

	/**
	 * 客户端相关配置
	 * @return ClientSettings
	 */
	public ClientSettings clientSettings(boolean requireAuthorizationConsent) {
		return ClientSettings.builder()
			// 是否需要用户授权确认
			.requireAuthorizationConsent(requireAuthorizationConsent)
			.build();
	}

}
