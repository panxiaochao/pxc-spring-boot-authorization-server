package io.github.panxiaochao.authorization.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Collections;

/**
 * <p>
 * SecurityConfiguration 配置类.
 * </p>
 *
 * @author Lypxc
 * @since 2023-07-17
 */
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class SecurityConfiguration {

	/**
	 * Security过滤器链
	 * @param httpSecurity httpSecurity
	 * @return SecurityFilterChain
	 */
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE + 1)
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity httpSecurity) {
		// LOGGER.info(">>> 自定义 DefaultSecurityFilterChain 配置");
		try {
			// 基础配置
			httpSecurity
				// cors
				.cors()
				.configurationSource(corsConfigurationSource())
				// CSRF禁用，因为不使用session
				.and()
				.csrf()
				.disable()
				// 防止iframe 造成跨域
				.headers()
				.frameOptions()
				.disable();

			// 基于token，所以不需要session
			// .and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
			// 禁用缓存
			// .and().headers().cacheControl();
			// 过滤请求
			httpSecurity.authorizeHttpRequests(authorize -> authorize
				// 只放行OAuth相关接口
				// .antMatchers(SecurityConstants.TOKEN_ENDPOINT).permitAll()
				// 除上面外的所有请求全部需要鉴权认证
				.anyRequest()
				.authenticated()).formLogin(Customizer.withDefaults());
			return httpSecurity.build();
		}
		catch (Exception e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * security cors 配置
	 * @return CorsConfigurationSource
	 */
	private CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration configuration = new CorsConfiguration();
		configuration.setAllowedOrigins(Collections.singletonList("*"));
		configuration.setAllowedMethods(Collections.singletonList("*"));
		configuration.setAllowedHeaders(Collections.singletonList("*"));
		configuration.setAllowCredentials(true);
		configuration.setMaxAge(3600L);
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

}
