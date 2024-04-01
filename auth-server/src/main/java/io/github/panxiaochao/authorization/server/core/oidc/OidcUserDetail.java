package io.github.panxiaochao.authorization.server.core.oidc;

import lombok.Getter;
import org.springframework.util.Assert;

import java.io.Serializable;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

/**
 * <p>
 * 从OAuth 2.0受保护资源UserInfo终结点返回的UserInfo响应的表示形式, OidcUserDetails包含一组关于最终用户身份验证的“标准声明”。
 * </p>
 *
 * @author Lypxc
 * @since 2024-03-28
 * @version 1.0
 */
@Getter
public class OidcUserDetail implements Serializable {

	private static final long serialVersionUID = 1L;

	private final Map<String, Object> claims;

	/**
	 * Constructs a {@code OidcUserDetail} using the provided parameters.
	 * @param claims the claims about the authentication of the End-User
	 */
	private OidcUserDetail(Map<String, Object> claims) {
		Assert.notEmpty(claims, "claims cannot be empty");
		this.claims = Collections.unmodifiableMap(new LinkedHashMap<>(claims));
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || this.getClass() != obj.getClass()) {
			return false;
		}
		OidcUserDetail that = (OidcUserDetail) obj;
		return this.getClaims().equals(that.getClaims());
	}

	@Override
	public int hashCode() {
		return this.getClaims().hashCode();
	}

	/**
	 * Create a {@link Builder}
	 * @return the {@link Builder} for further configuration
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * A builder for {@link OidcUserDetail}s
	 *
	 * @author Josh Cummings
	 */
	public static final class Builder {

		private final Map<String, Object> claims = new LinkedHashMap<>();

		private Builder() {
		}

		/**
		 * Use this claim in the resulting {@link OidcUserDetail}
		 * @param name The claim name
		 * @param value The claim value
		 * @return the {@link Builder} for further configurations
		 */
		public Builder claim(String name, Object value) {
			this.claims.put(name, value);
			return this;
		}

		/**
		 * Use this claims in the resulting {@link OidcUserDetail}
		 * @param claims The claims collections
		 * @return the {@link Builder} for further configurations
		 */
		public Builder claims(Map<String, Object> claims) {
			this.claims.putAll(claims);
			return this;
		}

		/**
		 * Provides access to every {@link #claim(String, Object)} declared so far with
		 * the possibility to add, replace, or remove.
		 * @param claimsConsumer the consumer
		 * @return the {@link Builder} for further configurations
		 */
		public Builder claims(Consumer<Map<String, Object>> claimsConsumer) {
			claimsConsumer.accept(this.claims);
			return this;
		}

		/**
		 * Use this address in the resulting {@link OidcUserDetail}
		 * @param address The address to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder address(String address) {
			return this.claim(OidcUserDetailStandardClaimNames.ADDRESS, address);
		}

		/**
		 * Use this birthdate in the resulting {@link OidcUserDetail}
		 * @param birthdate The birthdate to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder birthdate(String birthdate) {
			return this.claim(OidcUserDetailStandardClaimNames.BIRTHDATE, birthdate);
		}

		/**
		 * Use this email in the resulting {@link OidcUserDetail}
		 * @param email The email to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder email(String email) {
			return this.claim(OidcUserDetailStandardClaimNames.EMAIL, email);
		}

		/**
		 * Use this verified-email indicator in the resulting {@link OidcUserDetail}
		 * @param emailVerified The verified-email indicator to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder emailVerified(Boolean emailVerified) {
			return this.claim(OidcUserDetailStandardClaimNames.EMAIL_VERIFIED, emailVerified);
		}

		/**
		 * Use this family name in the resulting {@link OidcUserDetail}
		 * @param familyName The family name to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder familyName(String familyName) {
			return claim(OidcUserDetailStandardClaimNames.FAMILY_NAME, familyName);
		}

		/**
		 * Use this gender in the resulting {@link OidcUserDetail}
		 * @param gender The gender to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder gender(String gender) {
			return this.claim(OidcUserDetailStandardClaimNames.GENDER, gender);
		}

		/**
		 * Use this given name in the resulting {@link OidcUserDetail}
		 * @param givenName The given name to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder givenName(String givenName) {
			return claim(OidcUserDetailStandardClaimNames.GIVEN_NAME, givenName);
		}

		/**
		 * Use this locale in the resulting {@link OidcUserDetail}
		 * @param locale The locale to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder locale(String locale) {
			return this.claim(OidcUserDetailStandardClaimNames.LOCALE, locale);
		}

		/**
		 * Use this middle name in the resulting {@link OidcUserDetail}
		 * @param middleName The middle name to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder middleName(String middleName) {
			return claim(OidcUserDetailStandardClaimNames.MIDDLE_NAME, middleName);
		}

		/**
		 * Use this name in the resulting {@link OidcUserDetail}
		 * @param name The name to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder name(String name) {
			return claim(OidcUserDetailStandardClaimNames.NAME, name);
		}

		/**
		 * Use this nickname in the resulting {@link OidcUserDetail}
		 * @param nickname The nickname to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder nickname(String nickname) {
			return claim(OidcUserDetailStandardClaimNames.NICKNAME, nickname);
		}

		/**
		 * Use this picture in the resulting {@link OidcUserDetail}
		 * @param picture The picture to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder picture(String picture) {
			return this.claim(OidcUserDetailStandardClaimNames.PICTURE, picture);
		}

		/**
		 * Use this phone number in the resulting {@link OidcUserDetail}
		 * @param phoneNumber The phone number to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder phoneNumber(String phoneNumber) {
			return this.claim(OidcUserDetailStandardClaimNames.PHONE_NUMBER, phoneNumber);
		}

		/**
		 * Use this verified-phone-number indicator in the resulting
		 * {@link OidcUserDetail}
		 * @param phoneNumberVerified The verified-phone-number indicator to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder phoneNumberVerified(String phoneNumberVerified) {
			return this.claim(OidcUserDetailStandardClaimNames.PHONE_NUMBER_VERIFIED, phoneNumberVerified);
		}

		/**
		 * Use this preferred username in the resulting {@link OidcUserDetail}
		 * @param preferredUsername The preferred username to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder preferredUsername(String preferredUsername) {
			return claim(OidcUserDetailStandardClaimNames.PREFERRED_USERNAME, preferredUsername);
		}

		/**
		 * Use this profile in the resulting {@link OidcUserDetail}
		 * @param profile The profile to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder profile(String profile) {
			return claim(OidcUserDetailStandardClaimNames.PROFILE, profile);
		}

		/**
		 * Use this subject in the resulting {@link OidcUserDetail}
		 * @param subject The subject to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder subject(String subject) {
			return this.claim(OidcUserDetailStandardClaimNames.SUB, subject);
		}

		/**
		 * Use this updated-at {@link Instant} in the resulting {@link OidcUserDetail}
		 * @param updatedAt The updated-at {@link Instant} to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder updatedAt(String updatedAt) {
			return this.claim(OidcUserDetailStandardClaimNames.UPDATED_AT, updatedAt);
		}

		/**
		 * Use this website in the resulting {@link OidcUserDetail}
		 * @param website The website to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder website(String website) {
			return this.claim(OidcUserDetailStandardClaimNames.WEBSITE, website);
		}

		/**
		 * Use this zoneinfo in the resulting {@link OidcUserDetail}
		 * @param zoneinfo The zoneinfo to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder zoneinfo(String zoneinfo) {
			return this.claim(OidcUserDetailStandardClaimNames.ZONEINFO, zoneinfo);
		}

		/**
		 * Use this username in the resulting {@link OidcUserDetail}
		 * @param username The username to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder username(String username) {
			return this.claim(OidcUserDetailStandardClaimNames.USERNAME, username);
		}

		/**
		 * Use this role's in the resulting {@link OidcUserDetail}
		 * @param roles The roles to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder roles(List<String> roles) {
			return this.claim(OidcUserDetailStandardClaimNames.ROLES, roles);
		}

		/**
		 * Use this unionId in the resulting {@link OidcUserDetail}
		 * @param unionId The unionId to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder unionId(String unionId) {
			return this.claim(OidcUserDetailStandardClaimNames.UNION_ID, unionId);
		}

		/**
		 * Use this tenantId in the resulting {@link OidcUserDetail}
		 * @param tenantId The tenantId to use
		 * @return the {@link Builder} for further configurations
		 */
		public Builder tenantId(String tenantId) {
			return this.claim(OidcUserDetailStandardClaimNames.TENANT_ID, tenantId);
		}

		/**
		 * Build the {@link OidcUserDetail}
		 * @return The constructed {@link OidcUserDetail}
		 */
		public OidcUserDetail build() {
			return new OidcUserDetail(this.claims);
		}

	}

}
