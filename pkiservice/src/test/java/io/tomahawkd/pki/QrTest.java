package io.tomahawkd.pki;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.exceptions.MalformedJsonException;
import io.tomahawkd.pki.util.Message;
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
public class QrTest {

	@Autowired
	private TestRestTemplate testRestTemplate;

	@Test
	public void qr()
			throws InvalidKeySpecException, NoSuchAlgorithmException, CipherErrorException, MalformedJsonException {

		String auth = this.testRestTemplate.getForObject("/keys/auth", String.class);
		System.out.println(auth);
		PublicKey k = SecurityFunctions.readPublicKey(auth);

		// genqr
		byte[] ivqrgen = SecurityFunctions.generateRandom(16);
		byte[] kctqrgen = SecurityFunctions.generateRandom(32);
		String ivStringqrgen = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(k, ivqrgen));
		String kctStringqrgen = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(k, kctqrgen));

		String system = "cab4af0fc499491eb9bb16120e3ae195";

		int tqrgen = SecurityFunctions.generateRandom();
		String tStringqrgen = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(k,
				ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(tqrgen).array()));

		Map<String, String> genqrRequestMap = new HashMap<>();
		genqrRequestMap.put("K", kctStringqrgen);
		genqrRequestMap.put("iv", ivStringqrgen);
		genqrRequestMap.put("system", system);
		genqrRequestMap.put("T", tStringqrgen);

		String qrgenrequest = new Gson().toJson(genqrRequestMap);
		System.out.println(qrgenrequest);
		String resqrgen = this.testRestTemplate.postForObject("/qr/genqr", qrgenrequest, String.class);
		System.out.println(resqrgen);

		Map<String, String> resultqrgen = Utils.wrapMapFromJson(resqrgen);
		System.out.println(resultqrgen.get("M"));
		assertThat(resultqrgen.get("M")).contains("\"status\":0");

		String tR = resultqrgen.get("T");
		PrivateKey kpr = SecurityFunctions.readPrivateKey("MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCILsWGIuVJwrvwFOsn070JQttNEONkP5DDMKtHPVK8/GaKz6yATn1Wt8glTGnl04KVHJWgyoQiHoZF513RE+n0oeg8doHriKVnkW5GSNsLFLzLhpt1TUmlXvVuQSxNMu5+mvaeKSpPZtdL9mj8A28l2oFjg5YEimv/+v+va2tWNbEAvOYvpL+xgfmA8ZUlwwT4FcnSXySLMV5y8Ecik2Z86Vh3aHHH09aesKjYfiE7J37ASumeNIFhZzQEyPikMFlmUbW2V6C1c0r/lRaN7EEeuPZT8DYJkYL+fmTjKMKDQ1b45hgwpz5nemcKOmwive8PuqpCQbtggg0v6BOrSDYjAgMBAAECggEAVukKlDV3AWDvEiQ3gz5lWSC61m8dv9+1YmyQErH3OLcYNiSdYXE2Gn7Fk9A1kUAwCTup3mkAdMnoRXqH7CP6Xm5pyRSUi520eeldaCuc53B/oKAyXGVLx+dXWNrtDAOiI1iAZaW949itNER48cS7TXwqsTjMJ++zRzWHsgsrAGPokzB8Of0e1aqSq8KZ8OubLTYesakMpEOGmngv6Ht0VAVkZgrUVR1Op/aDkUt8636/EIj256BH6SGPD0l7FGFGpIlWjf5Lhr1TF3kNszCIo7YfRoXgJlsKYj6eNeSEVXnss5jLgfpHoznKpDPuTpBt3LRz9eiAFHUXVemd4I9EkQKBgQDZWrOSQeFqDV6vai3mS2hP86xB/OGQg96hiKYj3XHF5OqWF6TVgjgMYaKFFhETuYYO+X6QOpcmF0bRSAJKTOYnHpTQ6qB0xEv5V4wdV5n6+VltxWbFnCVJpLxUz5kzftOdVeK1yCSMV2DjROeYSGZ7KbGnO2leAz58HcYAm3S8awKBgQCgZWOIZJITbaR0DorliE79zNJkR6f7GyjUfgiIiivNGEA5YhOLhqGi/yxqbkP08BTYjLflp49UqISINzS6zbx6BDbGhtPWiHDcV2S1yNzcYlsHVO1yra7pPZi1UjCbMQfTELTDSeoL789ks7LMMu3ARCh0xCm6UGvsB/kUOtRbKQKBgGPOoJLSqb3XMdl++mC708SS8lDC3JlN1Jd8dj4V276xpX8SkGBykWYuF0DhpynVkVei/ZkhLnMRUTWcyWBw+2aPRmrAsrmrwe9XYkG/DjgO9B/R+6VWVFEC0nBne8QHwwiGfbpXk2DWZuk1pNtqs5RuyuMuBu5isvive1KgD/TNAoGAVuDUGsquvMtEqoA+B7nfX2WUCDEv8blyUja6FIsS0pJyJyLSh16zKoCg5D05nfB0uh7udPxfjHGC5+1PKGfL0SN7L+lT0P4yc4b6y+QyjUTRHZWIz/b3qOpuTrhoD4dtP4vq/WSJ21FXuqoDDMwBL4U7jJO8LmjlLAHdjnGXGJECgYA1zCwvw16tykp3A7aUcb0NWNSS4XfUUJelhzn4d6oQf7babuQyJQBDnyIRN5rNOHs3ouS0kDscG7l/r4v4ZPDOgs5aC7wlwj1RS2DEfZ0OlAAYmYdJhlwkVwMW/+OoCOa5NfDnlsOU11zL+J2XHvFE4K3EgpmRmfLdif3m5ojyGQ==");
		int tRes = ByteBuffer.wrap(SecurityFunctions.decryptAsymmetric(kpr, Utils.base64Decode(tR)))
				.order(ByteOrder.LITTLE_ENDIAN).getInt();
		assertThat(tRes).isEqualTo(tqrgen + 1);

		String nonR = resultqrgen.get("nonce2");
		int nonRes = ByteBuffer.wrap(SecurityFunctions.decryptSymmetric(kctqrgen, ivqrgen, Utils.base64Decode(nonR)))
				.order(ByteOrder.LITTLE_ENDIAN).getInt();
		System.out.println(nonRes);

		// query1
		String nonceStatus =
				Utils.base64Encode(
						SecurityFunctions.encryptAsymmetric(k,
								ByteBuffer.allocate(Integer.BYTES)
										.order(ByteOrder.LITTLE_ENDIAN)
										.putInt(nonRes).array()));

		int tquery1 = SecurityFunctions.generateRandom();
		String tquery1String = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(k,
				ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(tquery1).array()));

		Map<String, String> query1RequestMap = new HashMap<>();
		query1RequestMap.put("T", tquery1String);
		query1RequestMap.put("nonce2", nonceStatus);
		query1RequestMap.put("system", system);
		query1RequestMap.put("D", "JavaTest;127.0.0.1");
		String query1Response = this.testRestTemplate.postForObject("/qr/query", new Gson().toJson(query1RequestMap), String.class);
		System.out.println(query1Response);

		Map<String, String> query1ResponseMap = new Gson().fromJson(query1Response, new TypeToken<Map<String, String>>() {
		}.getType());

		String tquery1res = query1ResponseMap.get("T");
		int tquery1resInt = ByteBuffer.wrap(SecurityFunctions.decryptAsymmetric(kpr, Utils.base64Decode(tquery1res)))
				.order(ByteOrder.LITTLE_ENDIAN).getInt();
		assertThat(tquery1resInt).isEqualTo(tquery1 + 1);

		String query1Message = query1ResponseMap.get("M");
		System.out.println(query1Message);


		// get token
		byte[] ivtoken = SecurityFunctions.generateRandom(16);
		byte[] kcttoken = SecurityFunctions.generateRandom(32);
		String ivtokenString = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(k, ivtoken));
		String kcttokenString = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(k, kcttoken));

		String userTag = Utils.base64Encode(SecurityFunctions.generateHash("1"));
		String idString =
				Utils.base64Encode(SecurityFunctions.encryptAsymmetric(k, (userTag + ";" + system).getBytes()));

		Map<String, String> tokenrequest = new HashMap<>();
		tokenrequest.put("K", kcttokenString);
		tokenrequest.put("iv", ivtokenString);
		tokenrequest.put("id", idString);
		tokenrequest.put("T", tquery1String);
		tokenrequest.put("D", "JavaTest;127.0.0.1");

		String tokenre = new Gson().toJson(tokenrequest);
		System.out.println(tokenre);
		String tokenres = this.testRestTemplate.postForObject("/token/init", tokenre, String.class);

		System.out.println(tokenres);
		Map<String, String> tokenresult = Utils.wrapMapFromJson(tokenres);
		System.out.println(tokenresult.get("M"));
		assertThat(tokenresult.get("M")).contains("\"status\":0");

		String tokenR = tokenresult.get("T");
		int tokenRes = ByteBuffer.wrap(SecurityFunctions.decryptAsymmetric(kpr, Utils.base64Decode(tokenR)))
				.order(ByteOrder.LITTLE_ENDIAN).getInt();
		assertThat(tokenRes).isEqualTo(tquery1 + 1);

		String[] kp =
				new String(SecurityFunctions.decryptSymmetric(kcttoken, ivtoken, Utils.base64Decode(tokenresult.get("KP"))))
						.split(";");
		KeyPair keyPair = SecurityFunctions.readKeysFromString(kp[1], kp[0]);


		byte[] etoken = SecurityFunctions.decryptAsymmetric(keyPair.getPrivate(),
				Utils.base64Decode(tokenresult.get("EToken")));

		int nonce = ByteBuffer.wrap(etoken).order(ByteOrder.LITTLE_ENDIAN).getInt();
		byte[] token = new byte[etoken.length - Integer.BYTES];
		System.arraycopy(etoken, Integer.BYTES, token, 0, etoken.length - Integer.BYTES);

		nonce++;
		byte[] tokenArr = ByteBuffer.allocate(token.length + Integer.BYTES)
				.order(ByteOrder.LITTLE_ENDIAN).putInt(nonce).put(token).array();
		String etokenReq = Utils.base64Encode(
				SecurityFunctions.encryptAsymmetric(k, tokenArr));

		// update to scanned
		int tReq = SecurityFunctions.generateRandom();
		String tStringReq = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(k,
				ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(tReq).array()));

		Message<String> update1Message = new Message<>();
		update1Message.setStatus(1);
		update1Message.setMessage(Utils.base64Encode(SecurityFunctions.encryptAsymmetric(k,
				ByteBuffer.allocate(Integer.BYTES)
						.order(ByteOrder.LITTLE_ENDIAN)
						.putInt(nonRes).array())));

		TokenRequestMessage<String> update1tokenRequestMessage = new TokenRequestMessage<>();
		update1tokenRequestMessage.setToken(etokenReq);
		update1tokenRequestMessage.setTime(tStringReq);
		update1tokenRequestMessage.setDevice("JavaTest;127.0.0.1");
		update1tokenRequestMessage.setMessage(update1Message);

		String update1tokenRequest = update1tokenRequestMessage.toJson();
		System.out.println(update1tokenRequest);

		String resStatus = this.testRestTemplate.postForObject("/qr/update", update1tokenRequest, String.class);
		System.out.println(resStatus);


		// query 2
		int tquery2 = SecurityFunctions.generateRandom();
		String tquery2String = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(k,
				ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(tquery2).array()));

		Map<String, String> query2RequestMap = new HashMap<>();
		query2RequestMap.put("T", tquery2String);
		query2RequestMap.put("nonce2", nonceStatus);
		query2RequestMap.put("system", system);
		query2RequestMap.put("D", "JavaTest;127.0.0.1");
		String query2Response = this.testRestTemplate.postForObject("/qr/query", new Gson().toJson(query2RequestMap), String.class);
		System.out.println(query2Response);

		Map<String, String> query2ResponseMap = new Gson().fromJson(query2Response, new TypeToken<Map<String, String>>() {
		}.getType());

		String tquery2res = query2ResponseMap.get("T");
		int tquery2resInt = ByteBuffer.wrap(SecurityFunctions.decryptAsymmetric(kpr, Utils.base64Decode(tquery2res)))
				.order(ByteOrder.LITTLE_ENDIAN).getInt();
		assertThat(tquery2resInt).isEqualTo(tquery2 + 1);

		String query2Message = query2ResponseMap.get("M");
		System.out.println(query2Message);


		// update to confirmed
		int tReqcon = SecurityFunctions.generateRandom();
		String tStringReqcon = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(k,
				ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(tReqcon).array()));

		Message<String> update2Message = new Message<>();
		update2Message.setStatus(2);
		update2Message.setMessage(Utils.base64Encode(SecurityFunctions.encryptAsymmetric(k,
				"1".getBytes())));

		nonce++;
		byte[] tokenArrCon = ByteBuffer.allocate(token.length + Integer.BYTES)
				.order(ByteOrder.LITTLE_ENDIAN).putInt(nonce).put(token).array();
		String etokenReqCon = Utils.base64Encode(
				SecurityFunctions.encryptAsymmetric(k, tokenArrCon));

		TokenRequestMessage<String> update2tokenRequestMessage = new TokenRequestMessage<>();
		update2tokenRequestMessage.setToken(etokenReqCon);
		update2tokenRequestMessage.setTime(tStringReqcon);
		update2tokenRequestMessage.setDevice("JavaTest;127.0.0.1");
		update2tokenRequestMessage.setMessage(update2Message);

		String update2tokenRequest = update2tokenRequestMessage.toJson();
		System.out.println(update2tokenRequest);

		String resStatus2 = this.testRestTemplate.postForObject("/qr/update", update2tokenRequest, String.class);
		System.out.println(resStatus2);


		// query 3
		int tquery3 = SecurityFunctions.generateRandom();
		String tquery3String = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(k,
				ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(tquery3).array()));

		Map<String, String> query3RequestMap = new HashMap<>();
		query3RequestMap.put("T", tquery3String);
		query3RequestMap.put("nonce2", nonceStatus);
		query3RequestMap.put("system", system);
		query3RequestMap.put("D", "JavaTest;127.0.0.1");
		String query3Response = this.testRestTemplate.postForObject("/qr/query", new Gson().toJson(query3RequestMap), String.class);
		System.out.println(query3Response);

		Map<String, String> query3ResponseMap = new Gson().fromJson(query3Response, new TypeToken<Map<String, String>>() {
		}.getType());

		String tquery3res = query3ResponseMap.get("T");
		int tquery3resInt = ByteBuffer.wrap(SecurityFunctions.decryptAsymmetric(kpr, Utils.base64Decode(tquery3res)))
				.order(ByteOrder.LITTLE_ENDIAN).getInt();
		assertThat(tquery3resInt).isEqualTo(tquery3 + 1);

		String query3Message = query3ResponseMap.get("M");
		System.out.println(query3Message);

		String confirmKP = query3ResponseMap.get("KP");
		String confirmEToken = query3ResponseMap.get("EToken");

		String[] kpconfirm =
				new String(SecurityFunctions.decryptSymmetric(kctqrgen, ivqrgen, Utils.base64Decode(confirmKP)))
						.split(";");
		KeyPair keyPairconfirm = SecurityFunctions.readKeysFromString(kpconfirm[1], kpconfirm[0]);


		byte[] etokenconfirm = SecurityFunctions.decryptAsymmetric(keyPairconfirm.getPrivate(),
				Utils.base64Decode(confirmEToken));

		int nonceconfirm = ByteBuffer.wrap(etokenconfirm).order(ByteOrder.LITTLE_ENDIAN).getInt();
		byte[] tokenconfirm = new byte[etokenconfirm.length - Integer.BYTES];
		System.arraycopy(etokenconfirm, Integer.BYTES, tokenconfirm, 0, etokenconfirm.length - Integer.BYTES);

		nonceconfirm++;
		byte[] tokenArrconfirm = ByteBuffer.allocate(token.length + Integer.BYTES)
				.order(ByteOrder.LITTLE_ENDIAN).putInt(nonceconfirm).put(tokenconfirm).array();
		String etokenconfirmReq = Utils.base64Encode(
				SecurityFunctions.encryptAsymmetric(k, tokenArrconfirm));

		int tconfirmReq = SecurityFunctions.generateRandom();
		String tconfirmStringReq = Utils.base64Encode(SecurityFunctions.encryptAsymmetric(k,
				ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(tconfirmReq).array()));

		TokenRequestMessage<String> tokenRequestMessage = new TokenRequestMessage<>();
		tokenRequestMessage.setToken(etokenconfirmReq);
		tokenRequestMessage.setTime(tconfirmStringReq);
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
		assertThat(tRes2Int).isEqualTo(tconfirmReq + 1);

	}
}
