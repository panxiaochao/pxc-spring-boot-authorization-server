package io.github.panxiaochao.resource.server.config;

import io.github.panxiaochao.security.core.handler.ServerAccessDeniedHandler;
import io.github.panxiaochao.security.core.handler.ServerAuthenticationEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Collections;

/**
 * <p>
 * 资源服务器配置类
 * </p>
 *
 * @author Lypxc
 * @since 2023-07-21
 */
@EnableWebSecurity
public class ResourceServerConfig {

	/**
	 * Remote jwk url for JwtDecoder
	 * @return JwtDecoder
	 */
	@Bean
	public JwtDecoder jwtDecoder() {
		return NimbusJwtDecoder.withJwkSetUri("http://localhost:18000/oauth2/v1/jwks").build();
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		// @formatter:off
		http
				.cors().configurationSource(corsConfigurationSource())
				.and().headers().frameOptions().disable()
				// 设置session是无状态的
				.and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
				.and().csrf().disable()
				.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated())
				.exceptionHandling(exception -> exception
						.accessDeniedHandler(new ServerAccessDeniedHandler())
						.authenticationEntryPoint(new ServerAuthenticationEntryPoint())
				)
				.oauth2ResourceServer(auth2ResourceServer -> auth2ResourceServer
						.accessDeniedHandler(new ServerAccessDeniedHandler())
						.authenticationEntryPoint(new ServerAuthenticationEntryPoint())
						.jwt()
				);
		// @formatter:on
		return http.build();
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
