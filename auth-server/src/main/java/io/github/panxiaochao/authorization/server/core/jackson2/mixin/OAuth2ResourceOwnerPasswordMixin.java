package io.github.panxiaochao.authorization.server.core.jackson2.mixin;

import com.fasterxml.jackson.annotation.JsonAutoDetect;
import com.fasterxml.jackson.annotation.JsonAutoDetect.Visibility;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.annotation.JsonTypeInfo.Id;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import io.github.panxiaochao.authorization.server.core.jackson2.deserializer.OAuth2ResourceOwnerPassword;

/**
 * <p>
 * This mixin class is used to serialize/deserialize {@link OAuth2ResourceOwnerPassword}.
 * </p>
 *
 * @author Lypxc
 * @since 2023-07-17
 */
@JsonTypeInfo(use = Id.CLASS)
@JsonDeserialize(using = OAuth2ResourceOwnerPassword.class)
@JsonAutoDetect(fieldVisibility = Visibility.ANY, getterVisibility = Visibility.NONE,
		isGetterVisibility = Visibility.NONE)
@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class OAuth2ResourceOwnerPasswordMixin {

	OAuth2ResourceOwnerPasswordMixin() {
	}

}
