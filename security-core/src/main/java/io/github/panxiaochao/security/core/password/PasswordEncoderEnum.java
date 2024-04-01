package io.github.panxiaochao.security.core.password;

import lombok.AllArgsConstructor;
import lombok.Getter;

/**
 * <p>
 * 密码加密匹配 枚举类
 * </p>
 *
 * @author Lypxc
 * @since 2022-12-20
 */
@Getter
@AllArgsConstructor
public enum PasswordEncoderEnum {

	/**
	 * ldap password
	 */
	LDAP("ldap"),
	/**
	 * noop password
	 */
	NOOP("noop"),
	/**
	 * bcrypt password
	 */
	BCRYPT("bcrypt"),
	/**
	 * argon2 password
	 */
	ARGON2("argon2"),
	/**
	 * scrypt password
	 */
	SCRYPT("scrypt"),
	/**
	 * pbkdf2 password
	 */
	PBKDF2("pbkdf2"),
	/**
	 * MD4 password
	 */
	MD4("MD4"),
	/**
	 * MD5 password
	 */
	MD5("MD5"),
	/**
	 * SHA-1 password
	 */
	SHA_1("SHA-1"),
	/**
	 * SHA-256 password
	 */
	SHA_256("SHA-256"),
	/**
	 * SHA-384 password
	 */
	SHA_384("SHA-384"),
	/**
	 * SHA-512 password
	 */
	SHA_512("SHA-512"),
	/**
	 * Ssha256 password
	 */
	SHA256("Ssha256");

	private final String name;

}
