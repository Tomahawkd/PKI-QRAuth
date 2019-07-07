package io.tomahawkd.pki;

import com.google.gson.Gson;
import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.exceptions.MalformedJsonException;
import io.tomahawkd.pki.util.TokenRequestMessage;
import io.tomahawkd.pki.util.TokenResponseMessage;
import io.tomahawkd.pki.util.Utils;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.test.context.junit4.SpringRunner;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class TokenTest {

	@Autowired
	private TestRestTemplate testRestTemplate;

	@Test
	public void token()
			throws InvalidKeySpecException, NoSuchAlgorithmException, CipherErrorException, MalformedJsonException {

		String auth = this.testRestTemplate.getForObject("/keys/auth", String.class);
		System.out.println(auth);
		PublicKey k = SecurityFunctions.readPublicKey(auth);

		// client generate iv/kct
		byte[] iv = SecurityFunctions.generateRandom(16);
		byte[] kct = SecurityFunctions.generateRandom(32);
		String ivString = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(k, iv));
		String kctString = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(k, kct));

		// server user info and challenge number
		String userTag = Utils.base64Encode(SecurityFunctions.generateHash("1"));
		String system = "cab4af0fc499491eb9bb16120e3ae195";
		String idString =
				Utils.base64Encode(SecurityFunctions.encryptAsymmetric(k, (userTag + ";" + system).getBytes()));

		int t = SecurityFunctions.generateRandom();
		String tString = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(k,
				ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(t).array()));

		Map<String, String> request = new HashMap<>();
		request.put("K", kctString);
		request.put("iv", ivString);
		request.put("id", idString);
		request.put("T", tString);
		request.put("D", "JavaTest;127.0.0.1");

		String re = new Gson().toJson(request);
		System.out.println(re);
		String res = this.testRestTemplate.postForObject("/token/init", re, String.class);

		System.out.println(res);
		Map<String, String> result = Utils.wrapMapFromJson(res);
		System.out.println(result.get("M"));
		assertThat(result.get("M")).contains("\"status\":0");

		String tR = result.get("T");
		PrivateKey kpr = SecurityFunctions.readPrivateKey("MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCILsWGIuVJwrvwFOsn070JQttNEONkP5DDMKtHPVK8/GaKz6yATn1Wt8glTGnl04KVHJWgyoQiHoZF513RE+n0oeg8doHriKVnkW5GSNsLFLzLhpt1TUmlXvVuQSxNMu5+mvaeKSpPZtdL9mj8A28l2oFjg5YEimv/+v+va2tWNbEAvOYvpL+xgfmA8ZUlwwT4FcnSXySLMV5y8Ecik2Z86Vh3aHHH09aesKjYfiE7J37ASumeNIFhZzQEyPikMFlmUbW2V6C1c0r/lRaN7EEeuPZT8DYJkYL+fmTjKMKDQ1b45hgwpz5nemcKOmwive8PuqpCQbtggg0v6BOrSDYjAgMBAAECggEAVukKlDV3AWDvEiQ3gz5lWSC61m8dv9+1YmyQErH3OLcYNiSdYXE2Gn7Fk9A1kUAwCTup3mkAdMnoRXqH7CP6Xm5pyRSUi520eeldaCuc53B/oKAyXGVLx+dXWNrtDAOiI1iAZaW949itNER48cS7TXwqsTjMJ++zRzWHsgsrAGPokzB8Of0e1aqSq8KZ8OubLTYesakMpEOGmngv6Ht0VAVkZgrUVR1Op/aDkUt8636/EIj256BH6SGPD0l7FGFGpIlWjf5Lhr1TF3kNszCIo7YfRoXgJlsKYj6eNeSEVXnss5jLgfpHoznKpDPuTpBt3LRz9eiAFHUXVemd4I9EkQKBgQDZWrOSQeFqDV6vai3mS2hP86xB/OGQg96hiKYj3XHF5OqWF6TVgjgMYaKFFhETuYYO+X6QOpcmF0bRSAJKTOYnHpTQ6qB0xEv5V4wdV5n6+VltxWbFnCVJpLxUz5kzftOdVeK1yCSMV2DjROeYSGZ7KbGnO2leAz58HcYAm3S8awKBgQCgZWOIZJITbaR0DorliE79zNJkR6f7GyjUfgiIiivNGEA5YhOLhqGi/yxqbkP08BTYjLflp49UqISINzS6zbx6BDbGhtPWiHDcV2S1yNzcYlsHVO1yra7pPZi1UjCbMQfTELTDSeoL789ks7LMMu3ARCh0xCm6UGvsB/kUOtRbKQKBgGPOoJLSqb3XMdl++mC708SS8lDC3JlN1Jd8dj4V276xpX8SkGBykWYuF0DhpynVkVei/ZkhLnMRUTWcyWBw+2aPRmrAsrmrwe9XYkG/DjgO9B/R+6VWVFEC0nBne8QHwwiGfbpXk2DWZuk1pNtqs5RuyuMuBu5isvive1KgD/TNAoGAVuDUGsquvMtEqoA+B7nfX2WUCDEv8blyUja6FIsS0pJyJyLSh16zKoCg5D05nfB0uh7udPxfjHGC5+1PKGfL0SN7L+lT0P4yc4b6y+QyjUTRHZWIz/b3qOpuTrhoD4dtP4vq/WSJ21FXuqoDDMwBL4U7jJO8LmjlLAHdjnGXGJECgYA1zCwvw16tykp3A7aUcb0NWNSS4XfUUJelhzn4d6oQf7babuQyJQBDnyIRN5rNOHs3ouS0kDscG7l/r4v4ZPDOgs5aC7wlwj1RS2DEfZ0OlAAYmYdJhlwkVwMW/+OoCOa5NfDnlsOU11zL+J2XHvFE4K3EgpmRmfLdif3m5ojyGQ==");
		int tRes = ByteBuffer.wrap(SecurityFunctions.decryptAsymmetric(kpr, Utils.base64Decode(tR)))
				.order(ByteOrder.LITTLE_ENDIAN).getInt();
		assertThat(tRes).isEqualTo(t + 1);

		// public;private
		String[] kp =
				new String(SecurityFunctions.decryptSymmetric(kct, iv, Utils.base64Decode(result.get("KP"))))
						.split(";");
		KeyPair keyPair = SecurityFunctions.readKeysFromString(kp[1], kp[0]);


		byte[] etoken = SecurityFunctions.decryptAsymmetric(keyPair.getPrivate(),
				Utils.base64Decode(result.get("EToken")));

		int nonce = ByteBuffer.wrap(etoken).order(ByteOrder.LITTLE_ENDIAN).getInt();
		byte[] token = new byte[etoken.length - Integer.BYTES];
		System.arraycopy(etoken, Integer.BYTES, token, 0, etoken.length - Integer.BYTES);

		// next validate
		nonce++;
		byte[] tokenArr = ByteBuffer.allocate(token.length + Integer.BYTES)
				.order(ByteOrder.LITTLE_ENDIAN).putInt(nonce).put(token).array();
		String etokenReq = Utils.base64Encode(
				SecurityFunctions.encryptAsymmetric(k, tokenArr));

		int tReq = SecurityFunctions.generateRandom();
		String tStringReq = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(k,
				ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(tReq).array()));

		TokenRequestMessage<String> tokenRequestMessage = new TokenRequestMessage<>();
		tokenRequestMessage.setToken(etokenReq);
		tokenRequestMessage.setTime(tStringReq);
		tokenRequestMessage.setDevice("JavaTest;127.0.0.1");

		String reqJ = tokenRequestMessage.toJson();
		System.out.println(reqJ);
		String resAuth = this.testRestTemplate.postForObject("/token/validate", reqJ, String.class);
		System.out.println(resAuth);

		TokenResponseMessage<String> resultAuth = TokenResponseMessage.fromJson(resAuth);
		System.out.println(resultAuth.getMessage().toJson());
		assertThat(resultAuth.getMessage().getStatus()).isEqualTo(0);

		String tRes2 = resultAuth.getTime();
		int tRes2Int = ByteBuffer.wrap(SecurityFunctions.decryptAsymmetric(kpr, Utils.base64Decode(tRes2)))
				.order(ByteOrder.LITTLE_ENDIAN).getInt();
		assertThat(tRes2Int).isEqualTo(tReq + 1);
	}
}
