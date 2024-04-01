package io.github.panxiaochao.authorization.server.config;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.github.panxiaochao.authorization.server.core.authorization.oidc.OidcUserDetailAuthenticationConverter;
import io.github.panxiaochao.authorization.server.core.authorization.oidc.OidcUserDetailAuthenticationProvider;
import io.github.panxiaochao.authorization.server.core.authorization.oidc.OidcUserDetailAuthenticationSuccessHandler;
import io.github.panxiaochao.authorization.server.core.authorization.password.OAuth2ResourceOwnerPasswordAuthenticationConverter;
import io.github.panxiaochao.authorization.server.core.authorization.password.OAuth2ResourceOwnerPasswordAuthenticationProvider;
import io.github.panxiaochao.authorization.server.core.authorization.password.OAuth2ResourceOwnerPasswordAuthenticationToken;
import io.github.panxiaochao.authorization.server.core.jackson2.mixin.OAuth2ResourceOwnerPasswordMixin;
import io.github.panxiaochao.authorization.server.core.oidc.OidcUserDetailScopes;
import io.github.panxiaochao.authorization.server.core.oidc.OidcUserDetailStandardClaimNames;
import io.github.panxiaochao.authorization.server.core.service.UserDetailsServiceImpl;
import io.github.panxiaochao.authorization.server.properties.AuthorizationProperties;
import io.github.panxiaochao.security.core.constants.GlobalSecurityConstant;
import io.github.panxiaochao.security.core.handler.ServerAccessDeniedHandler;
import io.github.panxiaochao.security.core.handler.ServerAuthenticationEntryPoint;
import io.github.panxiaochao.security.core.handler.ServerAuthenticationFailureHandler;
import io.github.panxiaochao.security.core.handler.ServerAuthenticationSuccessHandler;
import io.github.panxiaochao.security.core.jose.Jwks;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.lob.DefaultLobHandler;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.oidc.OidcProviderConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.annotation.Resource;
import java.util.Arrays;
import java.util.List;
import java.util.function.Consumer;

/**
 * <p>
 * AuthorizationServerConfiguration 配置类.
 * </p>
 *
 * @author Lypxc
 * @since 2023-07-17
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfiguration {

	private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationServerConfiguration.class);

	private static final String CUSTOM_CONSENT_PAGE_URI = "/oauth2/consent";

	@Resource
	private PasswordEncoder passwordEncoder;

	@Resource
	private UserDetailsServiceImpl userDetailService;

	@Resource
	private AuthorizationProperties authorizationProperties;

	/**
	 * A Spring Security filter chain for the Protocol Endpoints.
	 * @param http HttpSecurity
	 * @return SecurityFilterChain
	 * @throws Exception 异常
	 */
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		// @formatter:off
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
		// custom converter and provider
		authorizationServerConfigurer
			.tokenEndpoint(tokenEndpoint -> tokenEndpoint
				.accessTokenRequestConverters(authenticationConverters -> {
					authenticationConverters.add(new OAuth2ResourceOwnerPasswordAuthenticationConverter());
					authenticationConverters.add(new OidcUserDetailAuthenticationConverter());
				})
				// 增加以下2个内置转换器
				// .accessTokenRequestConverter(new
				// OAuth2AuthorizationCodeRequestAuthenticationConverter())
				// .accessTokenRequestConverter(new
				// OAuth2AuthorizationConsentAuthenticationConverter())
				// 登录成功
				.accessTokenResponseHandler(new ServerAuthenticationSuccessHandler())
				// 登录失败
				.errorResponseHandler(new ServerAuthenticationFailureHandler()))
			// 客户端认证
			.clientAuthentication(clientAuthentication -> clientAuthentication
				// 登录失败
				.errorResponseHandler(new ServerAuthenticationFailureHandler()));
		// 自定义授权确认页面
		authorizationServerConfigurer
			.authorizationEndpoint(endpointConfigurer -> endpointConfigurer.consentPage(CUSTOM_CONSENT_PAGE_URI));
		// Enable OpenID Connect 1.0, 启用 OIDC 1.0, 自定义扩展处理 OIDC 1.0
		authorizationServerConfigurer.oidc(oidcConfigurer -> {
			// 提供用户自定义端点
			oidcConfigurer.userInfoEndpoint(userInfoEndpointCustomizer -> {
				userInfoEndpointCustomizer.userInfoResponseHandler(new OidcUserDetailAuthenticationSuccessHandler());
				userInfoEndpointCustomizer.userInfoRequestConverter(new OidcUserDetailAuthenticationConverter());
				userInfoEndpointCustomizer.errorResponseHandler(new ServerAuthenticationFailureHandler());
			});
			// 提供自定义客户端注册端点
			oidcConfigurer.clientRegistrationEndpoint(clientRegistrationEndpointCustomizer -> {
				clientRegistrationEndpointCustomizer.errorResponseHandler(new ServerAuthenticationFailureHandler());
				clientRegistrationEndpointCustomizer.clientRegistrationResponseHandler(new OidcUserDetailAuthenticationSuccessHandler());
			});
			// 提供 .well-known/openid-configuration 声明自定义能力配置项
			oidcConfigurer.providerConfigurationEndpoint(providerConfigurationEndpointCustomizer -> {
				providerConfigurationEndpointCustomizer.providerConfigurationCustomizer(oidcProviderConfigurationCustomizer());
			});
		});
		// 获取授权服务器相关的请求端点
		RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
		http.requestMatcher(endpointsMatcher)
			.authorizeRequests(authorizeRequests ->
					authorizeRequests.anyRequest().authenticated())
			// 忽略掉相关端点的 CSRF(跨站请求): 对授权端点的访问可以是跨站的
			.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
			// 授权异常处理
			.exceptionHandling(exception -> {
				exception.accessDeniedHandler(new ServerAccessDeniedHandler());
				exception.defaultAuthenticationEntryPointFor(
						new LoginUrlAuthenticationEntryPoint(GlobalSecurityConstant.LOGIN_PATH),
						new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
				);
			})
			// Accept access tokens for User Info and/or Client Registration
			.oauth2ResourceServer(oauth2ResourceServerCustomizer -> {
				oauth2ResourceServerCustomizer.jwt();
				oauth2ResourceServerCustomizer.accessDeniedHandler(new ServerAccessDeniedHandler());
				oauth2ResourceServerCustomizer.authenticationEntryPoint(new ServerAuthenticationEntryPoint());
			})
			.apply(authorizationServerConfigurer);
		// 这句意义在于初始化类，可以使用 http.getSharedObject()
		DefaultSecurityFilterChain securityFilterChain = http.build();
		// 注册自定义 providers
		customizerGrantAuthenticationProviders(http);
		// @formatter:on
		return securityFilterChain;
	}

	/**
	 * <p>
	 * 自定义授权模式实现: 密码模式
	 * </p>
	 */
	private void customizerGrantAuthenticationProviders(HttpSecurity http) {
		AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
		OAuth2AuthorizationService authorizationService = http.getSharedObject(OAuth2AuthorizationService.class);
		OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator = http.getSharedObject(OAuth2TokenGenerator.class);
		// 自定义密码模式
		OAuth2ResourceOwnerPasswordAuthenticationProvider resourceOwnerPasswordAuthenticationProvider = new OAuth2ResourceOwnerPasswordAuthenticationProvider(
				authenticationManager, authorizationService, tokenGenerator);
		// 自定义 DaoAuthenticationProvider 模式
		DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
		daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
		daoAuthenticationProvider.setUserDetailsService(userDetailService);
		// 自定义 OIDC OidcUserDetailAuthenticationProvider 模式
		OidcUserDetailAuthenticationProvider oidcUserDetailAuthenticationProvider = new OidcUserDetailAuthenticationProvider(
				authorizationService);

		http.authenticationProvider(resourceOwnerPasswordAuthenticationProvider);
		http.authenticationProvider(daoAuthenticationProvider);
		http.authenticationProvider(oidcUserDetailAuthenticationProvider);
	}

	/**
	 * 扩展 oidc 的默认能力配置项
	 */
	private Consumer<OidcProviderConfiguration.Builder> oidcProviderConfigurationCustomizer() {
		return builder -> builder.claims(claimsConsumer -> {
			claimsConsumer.put("claims_supported",
					Arrays.asList(OidcUserDetailStandardClaimNames.SUB, OidcUserDetailStandardClaimNames.NAME,
							OidcUserDetailStandardClaimNames.GIVEN_NAME, OidcUserDetailStandardClaimNames.FAMILY_NAME,
							OidcUserDetailStandardClaimNames.MIDDLE_NAME, OidcUserDetailStandardClaimNames.NICKNAME,
							OidcUserDetailStandardClaimNames.PREFERRED_USERNAME,
							OidcUserDetailStandardClaimNames.PROFILE, OidcUserDetailStandardClaimNames.PICTURE,
							OidcUserDetailStandardClaimNames.WEBSITE, OidcUserDetailStandardClaimNames.EMAIL,
							OidcUserDetailStandardClaimNames.EMAIL_VERIFIED, OidcUserDetailStandardClaimNames.GENDER,
							OidcUserDetailStandardClaimNames.BIRTHDATE, OidcUserDetailStandardClaimNames.ZONEINFO,
							OidcUserDetailStandardClaimNames.LOCALE, OidcUserDetailStandardClaimNames.PHONE_NUMBER,
							OidcUserDetailStandardClaimNames.PHONE_NUMBER_VERIFIED,
							OidcUserDetailStandardClaimNames.ADDRESS, OidcUserDetailStandardClaimNames.UPDATED_AT,
							OidcUserDetailStandardClaimNames.USERNAME, OidcUserDetailStandardClaimNames.ROLES,
							OidcUserDetailStandardClaimNames.UNION_ID, OidcUserDetailStandardClaimNames.TENANT_ID));
		}).scopes(strings -> {
			strings.add(OidcUserDetailScopes.PROFILE);
			strings.add(OidcUserDetailScopes.EMAIL);
			strings.add(OidcUserDetailScopes.ADDRESS);
			strings.add(OidcUserDetailScopes.PHONE);
			strings.add(OidcUserDetailScopes.OPENID);
			strings.add(OidcUserDetailScopes.USERNAME);
			strings.add(OidcUserDetailScopes.ROLES);
			strings.add(OidcUserDetailScopes.UNION_ID);
			strings.add(OidcUserDetailScopes.TENANT_ID);
		});
	}

	/**
	 * <p>
	 * 使用 JwtGenerator 代替 OAuth2AccessTokenGenerator(使用Base64StringKeyGenerator) 模式生成token
	 * </p>
	 * @return OAuth2TokenGenerator
	 */
	@Bean
	public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator(JWKSource<SecurityContext> jwkSource) {
		JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
		JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
		OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
		// 这里是有顺序的，自定义的需要放在最前面
		return new DelegatingOAuth2TokenGenerator(jwtGenerator, refreshTokenGenerator);
	}

	/**
	 * 客户端在认证中心的授权信息服务, 授权码、授权Token、刷新Token持久化, 对应 oauth2_authorization 表
	 * @param jdbcTemplate 数据源
	 * @param registeredClientRepository 注册客户端仓库
	 * @return OAuth2AuthorizationService
	 */
	@Bean
	public OAuth2AuthorizationService authorizationService(JdbcTemplate jdbcTemplate,
			RegisteredClientRepository registeredClientRepository) {
		JdbcOAuth2AuthorizationService authorizationService = new JdbcOAuth2AuthorizationService(jdbcTemplate,
				registeredClientRepository);
		JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper authorizationRowMapper = new JdbcOAuth2AuthorizationService.OAuth2AuthorizationRowMapper(
				registeredClientRepository);
		ObjectMapper objectMapper = new ObjectMapper();
		ClassLoader classLoader = JdbcOAuth2AuthorizationService.class.getClassLoader();
		List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
		objectMapper.registerModules(securityModules);
		objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
		// You will need to write the Mixin for your class so Jackson can marshall it.
		objectMapper.addMixIn(OAuth2ResourceOwnerPasswordAuthenticationToken.class,
				OAuth2ResourceOwnerPasswordMixin.class);
		authorizationRowMapper.setObjectMapper(objectMapper);
		authorizationRowMapper.setLobHandler(new DefaultLobHandler());
		authorizationService.setAuthorizationRowMapper(authorizationRowMapper);
		return authorizationService;
	}

	/**
	 * 授权码使用 JDBC 查询用户信息, 对应 oauth2_authorization_consent 表
	 * @param jdbcTemplate 数据源
	 * @param registeredClientRepository 注册客户端仓库
	 * @return OAuth2AuthorizationService
	 */
	@Bean
	public OAuth2AuthorizationConsentService authorizationConsentService(JdbcTemplate jdbcTemplate,
			RegisteredClientRepository registeredClientRepository) {
		return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
	}

	/**
	 * JSON Web Key (JWK) source.
	 * @return JWKSource
	 */
	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		// 首次启动初始化 KeyId, 解决每次启动Token验证失效
		// 是由于KeyId每次生成不一样导致，这里加不加缓存根据个人情况而定
		// String keyId = Base64.getEncoder()
		// .encodeToString(authorizationProperties.getSeed().getBytes(StandardCharsets.UTF_8));
		// if (!StringUtils.hasText(RedissonUtil.INSTANCE().get("RSAKey:" + keyId))) {
		// RedissonUtil.INSTANCE().set("RSAKey:" + keyId, keyId);
		// }
		RSAKey rsaKey = Jwks.generateRsaKey(authorizationProperties.getSeed());
		JWKSet jwkSet = new JWKSet(rsaKey);
		return new ImmutableJWKSet<>(jwkSet);
	}

	/**
	 * @param jwkSource jwkSource
	 * @return JwtDecoder
	 */
	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	/**
	 * （必需）自定义 OAuth2 授权服务器配置设置的，可以自定义请求端
	 * @return AuthorizationServerSettings
	 * @since 0.4.X
	 */
	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder()
			.authorizationEndpoint("/oauth2/v1/authorize")
			.tokenEndpoint("/oauth2/v1/token")
			.tokenIntrospectionEndpoint("/oauth2/v1/introspect")
			.tokenRevocationEndpoint("/oauth2/v1/revoke")
			.jwkSetEndpoint("/oauth2/v1/jwks")
			.oidcUserInfoEndpoint("/connect/v1/userinfo")
			.oidcClientRegistrationEndpoint("/connect/v1/register")
			// .issuer("http://127.0.0.1:18000/")
			.build();
	}

}
