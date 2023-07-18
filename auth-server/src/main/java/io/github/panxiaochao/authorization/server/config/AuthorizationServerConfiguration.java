package io.github.panxiaochao.authorization.server.config;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import io.github.panxiaochao.authorization.server.core.authorization.password.OAuth2ResourceOwnerPasswordAuthenticationConverter;
import io.github.panxiaochao.authorization.server.core.authorization.password.OAuth2ResourceOwnerPasswordAuthenticationProvider;
import io.github.panxiaochao.authorization.server.core.authorization.password.OAuth2ResourceOwnerPasswordAuthenticationToken;
import io.github.panxiaochao.authorization.server.core.handler.ServerAccessDeniedHandler;
import io.github.panxiaochao.authorization.server.core.handler.ServerAuthenticationFailureHandler;
import io.github.panxiaochao.authorization.server.core.jackson2.mixin.OAuth2ResourceOwnerPasswordMixin;
import io.github.panxiaochao.authorization.server.core.jose.Jwks;
import io.github.panxiaochao.authorization.server.core.service.UserDetailsServiceImpl;
import io.github.panxiaochao.authorization.server.properties.Oauth2Properties;
import io.github.panxiaochao.core.utils.JacksonUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.lob.DefaultLobHandler;
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
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.security.oauth2.server.authorization.web.authentication.*;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.annotation.Resource;
import java.util.Arrays;
import java.util.List;

/**
 * <p>
 * </p>
 *
 * @author Lypxc
 * @since 2023-07-17
 */
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfiguration {

	private static final Logger LOGGER = LoggerFactory.getLogger(AuthorizationServerConfiguration.class);

	@Resource
	private PasswordEncoder passwordEncoder;

	@Resource
	private UserDetailsServiceImpl userDetailService;

	@Resource
	private Oauth2Properties oauth2Properties;

	/**
	 * A Spring Security filter chain for the Protocol Endpoints.
	 * @param http HttpSecurity
	 * @return SecurityFilterChain
	 * @throws Exception 异常
	 */
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
		// 自定义授权确认页面
		// authorizationServerConfigurer.authorizationEndpoint(authorizationEndpoint ->
		// authorizationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI));
		//
		RequestMatcher endpointsMatcher = authorizationServerConfigurer.getEndpointsMatcher();
		http.requestMatcher(endpointsMatcher)
			.authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())
			.csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
			// 授权异常处理
			.exceptionHandling(exception -> {
				exception.accessDeniedHandler(new ServerAccessDeniedHandler())
					// .authenticationEntryPoint(new CustomAuthenticationEntryPoint())
					// 使用授权码模式登录
					.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"));
			})
			.apply(authorizationServerConfigurer);
		// custom converter and provider
		authorizationServerConfigurer
			.tokenEndpoint(tokenEndpoint -> tokenEndpoint
				.accessTokenRequestConverter(new OAuth2ResourceOwnerPasswordAuthenticationConverter())
				.errorResponseHandler(new ServerAuthenticationFailureHandler()))
			// 客户端认证
			.clientAuthentication(clientAuthentication -> clientAuthentication
				.errorResponseHandler(new ServerAuthenticationFailureHandler()));
		DefaultSecurityFilterChain securityFilterChain = http.build();
		// 注册自定义 providers
		customizerGrantAuthenticationProviders(http);
		return securityFilterChain;
	}

	/**
	 * request -> xToken 注入请求转换器
	 * @return DelegatingAuthenticationConverter
	 */
	private AuthenticationConverter accessTokenRequestConverter() {
		// @formatter:off
		return new DelegatingAuthenticationConverter(Arrays.asList(
				new OAuth2ResourceOwnerPasswordAuthenticationConverter(),
				new OAuth2RefreshTokenAuthenticationConverter(),
				new OAuth2ClientCredentialsAuthenticationConverter(),
				new OAuth2AuthorizationCodeAuthenticationConverter(),
				new OAuth2AuthorizationCodeRequestAuthenticationConverter()));
		// @formatter:on
	}

	/**
	 * <p>
	 * 自定义授权模式实现: 密码模式
	 * </p>
	 */
	private void customizerGrantAuthenticationProviders(HttpSecurity http) {
		OAuth2ResourceOwnerPasswordAuthenticationProvider resourceOwnerPasswordAuthenticationProvider = new OAuth2ResourceOwnerPasswordAuthenticationProvider();
		// 自定义 DaoAuthenticationProvider
		DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
		daoAuthenticationProvider.setPasswordEncoder(passwordEncoder);
		daoAuthenticationProvider.setUserDetailsService(userDetailService);
		// 密码模式
		http.authenticationProvider(resourceOwnerPasswordAuthenticationProvider);
		// 自定义Dao模式
		http.authenticationProvider(daoAuthenticationProvider);
	}

	/**
	 * 自定义生成Token机制
	 * @return OAuth2TokenGenerator
	 */
	@Bean
	public OAuth2TokenGenerator<? extends OAuth2Token> tokenGenerator(JWKSource<SecurityContext> jwkSource) {
		LOGGER.info(">>> 自定义 OAuth2TokenGenerator 配置");
		JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
		JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder);
		OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
		OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
		// OAuth2CustomizeAccessTokenGenerator customizeAccessTokenGenerator = new
		// OAuth2CustomizeAccessTokenGenerator(jwtEncoder);
		// 这里是有顺序的，自定义的需要放在最前面
		return new DelegatingOAuth2TokenGenerator(jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
	}

	/**
	 * 客户端在认证中心的授权信息服务
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
		ObjectMapper objectMapper = JacksonUtil.objectMapper();
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
	 * 授权码使用 JDBC 查询用户信息
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
	 * @return JWKSource
	 */
	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		RSAKey rsaKey = Jwks.generateRsaKey(oauth2Properties.getSeed());
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
		LOGGER.info(">>> 自定义 AuthorizationServerSettings 配置");
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
