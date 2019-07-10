package io.tomahawkd.pki.model;

import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.util.SecurityFunctions;
import io.tomahawkd.pki.util.Utils;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.sql.Timestamp;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class TokenModel {

	private int tokenId;
	private int userId;
	private Timestamp createDate;
	private Timestamp validBy;
	private int nonce;
	private String device;
	private String ip;

	private static final int TIMESTAMP_SIZE = Long.BYTES + Integer.BYTES;
	private static final int BYTE_ARRAY_SIZE = Integer.BYTES * 2 + TIMESTAMP_SIZE;

	public TokenModel(int userId, int nonce, String device, String ip) {
		this.userId = userId;
		this.nonce = nonce;
		this.device = device;
		this.ip = ip;
	}

	public TokenModel(int tokenId, int userId, Timestamp validBy) {
		this.tokenId = tokenId;
		this.userId = userId;
		this.validBy = validBy;
	}

	public TokenModel(int tokenId, int userId, Timestamp createDate, Timestamp validBy, int nonce,
	                  String device, String ip) {
		this.tokenId = tokenId;
		this.userId = userId;
		this.createDate = createDate;
		this.validBy = validBy;
		this.nonce = nonce;
		this.device = device;
		this.ip = ip;
	}

	public int getTokenId() {
		return tokenId;
	}

	public String getCompiledId() throws IOException {
		return Utils.base64Encode(SecurityFunctions.encryptUsingAuthenticateServerKey(
				ByteBuffer.allocate(16)
						.order(ByteOrder.LITTLE_ENDIAN)
						.putInt(tokenId).array()
		));
	}

	public int getUserId() {
		return userId;
	}

	public int getNonce() {
		return nonce;
	}

	public Timestamp getCreateDate() {
		return createDate;
	}

	public Timestamp getValidBy() {
		return validBy;
	}

	@Override
	public String toString() {
		return "TokenModel{" +
				"tokenId=" + tokenId +
				", userId=" + userId +
				", createDate=" + createDate +
				", validBy=" + validBy +
				'}';
	}

	public String toJson() throws CipherErrorException {
		return "{\"token\":\"" +
				Utils.base64Encode(SecurityFunctions.generateHash(String.valueOf(tokenId))) + "\"," +
				"\"create\":\"" + createDate.toString() + "\"," +
				"\"valid\":\"" + validBy.toString() + "\"," +
				"\"device\":\"" + device + "\"," +
				"\"ip\":" + ip + "\"" + "}";
	}

	public boolean equals(TokenModel token) {
		return token.tokenId == this.tokenId &&
				token.userId == this.userId &&
				token.validBy.equals(this.validBy);
	}

	private static byte[] toByteArray(int i) {
		return ByteBuffer.allocate(Integer.BYTES).order(ByteOrder.LITTLE_ENDIAN).putInt(i).array();
	}

	private static int toInt(byte[] b) {

		if (b.length != Integer.BYTES) throw new IllegalArgumentException("Illegal integer");
		return ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).getInt();
	}

	private static byte[] toByteArray(Timestamp t) {
		return ByteBuffer.allocate(TIMESTAMP_SIZE)
				.order(ByteOrder.LITTLE_ENDIAN)
				.putLong(t.getTime()).putInt(t.getNanos())
				.array();
	}

	private static Timestamp toTimeStamp(byte[] b) {

		if (b.length != TIMESTAMP_SIZE) throw new IllegalArgumentException("Illegal timestamp");
		long time = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).getLong();
		int nano = ByteBuffer.wrap(b).order(ByteOrder.LITTLE_ENDIAN).getInt(Long.BYTES);
		Timestamp t = new Timestamp(time);
		t.setNanos(nano);
		return t;
	}

	public byte[] serialize() {

		if (createDate == null) return null;

		byte[] result = new byte[BYTE_ARRAY_SIZE];
		byte[] tokenBytes = toByteArray(tokenId);
		System.arraycopy(tokenBytes, 0, result, 0, Integer.BYTES);
		byte[] userBytes = toByteArray(userId);
		System.arraycopy(userBytes, 0, result, Integer.BYTES, Integer.BYTES);
		byte[] validByBytes = toByteArray(validBy);
		System.arraycopy(validByBytes, 0, result, Integer.BYTES * 2, TIMESTAMP_SIZE);

		return result;
	}

	public String serializeToString() {
		return Base64.getEncoder().encodeToString(this.serialize());
	}

	public static TokenModel deserialize(byte[] data) throws CipherErrorException {

		if (data.length != BYTE_ARRAY_SIZE) throw new IllegalArgumentException("Array length invalid: " + data.length);

		byte[] tokenBytes = new byte[Integer.BYTES];
		System.arraycopy(data, 0, tokenBytes, 0, Integer.BYTES);
		int token = toInt(tokenBytes);
		byte[] userBytes = new byte[Integer.BYTES];
		System.arraycopy(data, Integer.BYTES, userBytes, 0, Integer.BYTES);
		int user = toInt(userBytes);
		byte[] validByBytes = new byte[TIMESTAMP_SIZE];
		System.arraycopy(data, Integer.BYTES * 2, validByBytes, 0, TIMESTAMP_SIZE);
		Timestamp validBy = toTimeStamp(validByBytes);

		return new TokenModel(token, user, validBy);
	}

	public static TokenModel deserializeFromString(String data)
			throws IllegalArgumentException, CipherErrorException {
		return deserialize(Base64.getDecoder().decode(data));
	}

	public Map<String, String> toMap() throws IOException {
		Map<String, String> data = new HashMap<>();
		data.put("id", Utils.base64Encode(SecurityFunctions.encryptUsingAuthenticateServerKey(
				ByteBuffer.allocate(16)
						.order(ByteOrder.LITTLE_ENDIAN)
						.putInt(tokenId).array()
				)
		));

		data.put("date", createDate.toString());
		data.put("device", device);
		data.put("ip", ip);
		return data;
	}
}
