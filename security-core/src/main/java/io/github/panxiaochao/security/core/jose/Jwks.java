package io.github.panxiaochao.security.core.jose;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * <p>
 * 获取 JWK 工具类.
 * </p>
 *
 * @author Lypxc
 * @since 2023-07-18
 */
public final class Jwks {

	private Jwks() {
	}

	public static RSAKey generateRsaKey() {
		return generateRsaKey(null);
	}

	public static RSAKey generateRsaKey(String seed) {
		return generateRsaKey(seed, UUID.randomUUID().toString());
	}

	public static RSAKey generateRsaKey(String seed, String keyId) {
		KeyPair keyPair = KeyGeneratorUtil.generateRsaKeyPair(seed);
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		return new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(keyId).build();
	}

	public static ECKey generateEc() {
		KeyPair keyPair = KeyGeneratorUtil.generateEcKey();
		ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
		ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
		Curve curve = Curve.forECParameterSpec(publicKey.getParams());
		return new ECKey.Builder(curve, publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
	}

	public static OctetSequenceKey generateSecret() {
		SecretKey secretKey = KeyGeneratorUtil.generateSecretKey();
		return new OctetSequenceKey.Builder(secretKey).keyID(UUID.randomUUID().toString()).build();
	}

}
