package io.github.panxiaochao.authorization.server.core.authorization.oidc;

import io.github.panxiaochao.authorization.server.core.oidc.OidcUserDetail;
import io.github.panxiaochao.authorization.server.core.oidc.OidcUserDetailStandardClaimNames;
import io.github.panxiaochao.core.utils.JacksonUtil;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.util.Assert;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/**
 * <p>
 * A {@link HttpMessageConverter} for an {@link OidcUserDetail OpenID Connect UserInfo
 * Response}.
 * </p>
 *
 * @author Lypxc
 * @since 2024-03-29
 * @version 1.0
 */
public class OidcUserDetailHttpMessageConverter extends AbstractHttpMessageConverter<OidcUserDetail> {

	private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<Map<String, Object>>() {
	};

	private final GenericHttpMessageConverter<Object> jsonMessageConverter = new MappingJackson2HttpMessageConverter(JacksonUtil.objectMapper());

	private Converter<Map<String, Object>, OidcUserDetail> userInfoConverter = new MapOidcUserDetailConverter();

	private Converter<OidcUserDetail, Map<String, Object>> userInfoParametersConverter = OidcUserDetail::getClaims;

	public OidcUserDetailHttpMessageConverter() {
		super(MediaType.APPLICATION_JSON, new MediaType("application", "*+json"));
	}

	@Override
	protected boolean supports(Class<?> clazz) {
		return OidcUserDetail.class.isAssignableFrom(clazz);
	}

	@Override
	@SuppressWarnings("unchecked")
	protected OidcUserDetail readInternal(Class<? extends OidcUserDetail> clazz, HttpInputMessage inputMessage)
			throws HttpMessageNotReadableException {
		try {
			Map<String, Object> userInfoParameters = (Map<String, Object>) this.jsonMessageConverter
				.read(STRING_OBJECT_MAP.getType(), null, inputMessage);
			return this.userInfoConverter.convert(userInfoParameters);
		}
		catch (Exception ex) {
			throw new HttpMessageNotReadableException(
					"An error occurred reading the UserInfo response: " + ex.getMessage(), ex, inputMessage);
		}
	}

	@Override
	protected void writeInternal(OidcUserDetail OidcUserDetail, HttpOutputMessage outputMessage)
			throws HttpMessageNotWritableException {
		try {
			Map<String, Object> userInfoResponseParameters = this.userInfoParametersConverter.convert(OidcUserDetail);
			this.jsonMessageConverter.write(userInfoResponseParameters, STRING_OBJECT_MAP.getType(),
					MediaType.APPLICATION_JSON, outputMessage);
		}
		catch (Exception ex) {
			throw new HttpMessageNotWritableException(
					"An error occurred writing the UserInfo response: " + ex.getMessage(), ex);
		}
	}

	/**
	 * Sets the {@link Converter} used for converting the UserInfo parameters to an
	 * {@link OidcUserDetail}.
	 * @param userInfoConverter the {@link Converter} used for converting to an
	 * {@link OidcUserDetail}
	 */
	public final void setUserInfoConverter(Converter<Map<String, Object>, OidcUserDetail> userInfoConverter) {
		Assert.notNull(userInfoConverter, "userInfoConverter cannot be null");
		this.userInfoConverter = userInfoConverter;
	}

	/**
	 * Sets the {@link Converter} used for converting the {@link OidcUserDetail} to a
	 * {@code Map} representation of the UserInfo.
	 * @param userInfoParametersConverter the {@link Converter} used for converting to a
	 * {@code Map} representation of the UserInfo
	 */
	public final void setUserInfoParametersConverter(
			Converter<OidcUserDetail, Map<String, Object>> userInfoParametersConverter) {
		Assert.notNull(userInfoParametersConverter, "userInfoParametersConverter cannot be null");
		this.userInfoParametersConverter = userInfoParametersConverter;
	}

	private static final class MapOidcUserDetailConverter implements Converter<Map<String, Object>, OidcUserDetail> {

		private static final ClaimConversionService CLAIM_CONVERSION_SERVICE = ClaimConversionService
			.getSharedInstance();

		private static final TypeDescriptor OBJECT_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Object.class);

		private static final TypeDescriptor BOOLEAN_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Boolean.class);

		private static final TypeDescriptor STRING_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(String.class);

		private static final TypeDescriptor INSTANT_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Instant.class);

		private static final TypeDescriptor STRING_OBJECT_MAP_DESCRIPTOR = TypeDescriptor.map(Map.class,
				STRING_TYPE_DESCRIPTOR, OBJECT_TYPE_DESCRIPTOR);

		private static final TypeDescriptor ARRAY_DESCRIPTOR = TypeDescriptor.array(STRING_TYPE_DESCRIPTOR);

		private final ClaimTypeConverter claimTypeConverter;

		private MapOidcUserDetailConverter() {
			Converter<Object, ?> booleanConverter = getConverter(BOOLEAN_TYPE_DESCRIPTOR);
			Converter<Object, ?> stringConverter = getConverter(STRING_TYPE_DESCRIPTOR);
			Converter<Object, ?> instantConverter = getConverter(INSTANT_TYPE_DESCRIPTOR);
			Converter<Object, ?> mapConverter = getConverter(STRING_OBJECT_MAP_DESCRIPTOR);
			Converter<Object, ?> arrayConverter = getConverter(ARRAY_DESCRIPTOR);

			Map<String, Converter<Object, ?>> claimConverters = new HashMap<>();
			claimConverters.put(OidcUserDetailStandardClaimNames.SUB, stringConverter);
			claimConverters.put(OidcUserDetailStandardClaimNames.NAME, stringConverter);
			claimConverters.put(OidcUserDetailStandardClaimNames.GIVEN_NAME, stringConverter);
			claimConverters.put(OidcUserDetailStandardClaimNames.FAMILY_NAME, stringConverter);
			claimConverters.put(OidcUserDetailStandardClaimNames.MIDDLE_NAME, stringConverter);
			claimConverters.put(OidcUserDetailStandardClaimNames.NICKNAME, stringConverter);
			claimConverters.put(OidcUserDetailStandardClaimNames.PREFERRED_USERNAME, stringConverter);
			claimConverters.put(OidcUserDetailStandardClaimNames.PROFILE, stringConverter);
			claimConverters.put(OidcUserDetailStandardClaimNames.PICTURE, stringConverter);
			claimConverters.put(OidcUserDetailStandardClaimNames.WEBSITE, stringConverter);
			claimConverters.put(OidcUserDetailStandardClaimNames.EMAIL, stringConverter);
			claimConverters.put(OidcUserDetailStandardClaimNames.EMAIL_VERIFIED, booleanConverter);
			claimConverters.put(OidcUserDetailStandardClaimNames.GENDER, stringConverter);
			claimConverters.put(OidcUserDetailStandardClaimNames.BIRTHDATE, stringConverter);
			claimConverters.put(OidcUserDetailStandardClaimNames.ZONEINFO, stringConverter);
			claimConverters.put(OidcUserDetailStandardClaimNames.LOCALE, stringConverter);
			claimConverters.put(OidcUserDetailStandardClaimNames.PHONE_NUMBER, stringConverter);
			claimConverters.put(OidcUserDetailStandardClaimNames.PHONE_NUMBER_VERIFIED, booleanConverter);
			claimConverters.put(OidcUserDetailStandardClaimNames.ADDRESS, mapConverter);
			claimConverters.put(OidcUserDetailStandardClaimNames.UPDATED_AT, instantConverter);
			claimConverters.put(OidcUserDetailStandardClaimNames.USERNAME, stringConverter);
			claimConverters.put(OidcUserDetailStandardClaimNames.ROLES, arrayConverter);
			claimConverters.put(OidcUserDetailStandardClaimNames.UNION_ID, stringConverter);
			claimConverters.put(OidcUserDetailStandardClaimNames.TENANT_ID, stringConverter);

			this.claimTypeConverter = new ClaimTypeConverter(claimConverters);
		}

		@Override
		public OidcUserDetail convert(Map<String, Object> source) {
			Map<String, Object> parsedClaims = this.claimTypeConverter.convert(source);
			return OidcUserDetail.builder().claims(parsedClaims).build();
		}

		private static Converter<Object, ?> getConverter(TypeDescriptor targetDescriptor) {
			return (source) -> CLAIM_CONVERSION_SERVICE.convert(source, OBJECT_TYPE_DESCRIPTOR, targetDescriptor);
		}

	}

}
