package io.github.panxiaochao.authorization.server.properties;

import io.github.panxiaochao.authorization.server.core.crypto.PasswordEncoderEnum;
import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>
 * 自定义属性.
 * </p>
 *
 * @author Lypxc
 * @since 2023-07-17
 */
@Getter
@Setter
@ConfigurationProperties(prefix = "auth.server", ignoreInvalidFields = true)
@Component
public class Oauth2Properties {

	/**
	 * CLIENT_ID
	 */
	private String clientId;

	/**
	 * CLIENT_SECRET
	 */
	private String clientSecret;

	/**
	 * CLIENT_SERVER
	 */
	private String clientServer;

	/**
	 * passwordEncoder 密码加密模式
	 */
	private PasswordEncoderEnum passwordEncoder;

	/**
	 * accessTokenTimeToLive, default seconds
	 */
	private long accessTokenTimeToLive = 3600;

	/**
	 * refreshTokenTimeToLive, default seconds
	 */
	private long refreshTokenTimeToLive = 7200;

	/**
	 * seed
	 */
	private String seed = "@123456$";

	/**
	 * 数据库加密是否是明文
	 */
	private boolean plainPassword;

	/**
	 * 白名单 Url
	 */
	private List<String> whiteUrls = new ArrayList<>();

}
