package io.github.panxiaochao.authorization.server.config;

import io.github.panxiaochao.authorization.server.properties.Oauth2Properties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import javax.annotation.Resource;
import java.time.Duration;

/**
 * <p>
 * </p>
 *
 * @author Lypxc
 * @since 2023-07-17
 */
@Configuration(proxyBeanMethods = false)
public class RegisteredClientConfiguration {

	@Resource
	private Oauth2Properties oauth2Properties;

	/**
	 * （必需）负责注册的 Client 信息
	 * @return RegisteredClientRepository
	 */
	@Bean
	public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
		// LOGGER.info(">>> 自定义 RegisteredClientRepository 配置");
		JdbcRegisteredClientRepository registeredClientRepository = new JdbcRegisteredClientRepository(jdbcTemplate);
		// 默认查询新建clientId
		// RegisteredClient registeredClient =
		// registeredClientRepository.findByClientId(oauth2Properties.getClientId());
		// if (Objects.isNull(registeredClient)) {
		// registeredClient = createRegisteredClient();
		// registeredClientRepository.save(registeredClient);
		// }
		// // AUTHORIZATION_CODE
		// registeredClient = registeredClientRepository.findByClientId("client_code");
		// if (Objects.isNull(registeredClient)) {
		// registeredClient = createAuthorizationCodeRegisteredClient();
		// registeredClientRepository.save(registeredClient);
		// }
		return registeredClientRepository;
	}

	/**
	 * 创建客户端秘钥记录
	 * @return RegisteredClient
	 */
	// private RegisteredClient createRegisteredClient() {
	// return RegisteredClient.withId(UUID.randomUUID().toString())
	// .clientId(selfProperties.getClientId())
	// .clientSecret(passwordEncoder.encode(selfProperties.getClientSecret()))
	// .clientName(selfProperties.getClientServer())
	// .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
	// .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
	// .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
	// .authorizationGrantType(AuthorizationGrantType.PASSWORD)
	// .scope(OidcScopes.OPENID)
	// .scope(OidcScopes.PROFILE)
	// .tokenSettings(tokenSettings())
	// .clientSettings(clientSettings(false))
	// .build();
	// }

	/**
	 * <p>
	 * http://127.0.0.1:18000/oauth2/authorize?response_type=code&client_id=client_code&scope=message.read&redirect_uri=https://www.baidu.com
	 * @return RegisteredClient
	 */
	// private RegisteredClient createAuthorizationCodeRegisteredClient() {
	// return RegisteredClient.withId(UUID.randomUUID().toString())
	// .clientId("client_code")
	// .clientSecret(passwordEncoder.encode("123456@"))
	// .clientName("client_code_server")
	// .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
	// .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
	// .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
	// .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
	// // 回调地址
	// .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
	// .redirectUri("http://127.0.0.1:8080/authorized")
	// .redirectUri("https://www.baidu.com")
	// .scope(OidcScopes.OPENID)
	// .scope(OidcScopes.PROFILE)
	// .scope("message.read")
	// .scope("message.write")
	// .tokenSettings(tokenSettings())
	// .clientSettings(clientSettings(true))
	// .build();
	// }

	/**
	 * JWT（Json Web Token）的配置项：TTL、是否复用refreshToken等等
	 * @return TokenSettings
	 */
	public TokenSettings tokenSettings() {
		return TokenSettings.builder()
			.accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
			.reuseRefreshTokens(true)
			.accessTokenTimeToLive(Duration.ofSeconds(oauth2Properties.getAccessTokenTimeToLive()))
			.refreshTokenTimeToLive(Duration.ofSeconds(oauth2Properties.getRefreshTokenTimeToLive()))
			.idTokenSignatureAlgorithm(SignatureAlgorithm.RS512)
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
