package io.tomahawkd.pki.model;

import io.tomahawkd.pki.exceptions.CipherErrorException;
import io.tomahawkd.pki.util.SecurityFunctions;
import io.tomahawkd.pki.util.Utils;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.sql.Timestamp;
import java.util.Base64;

public class TokenModel {

	private int tokenId;
	private int userId;
	private Timestamp createDate;
	private Timestamp validBy;

	private static final int TIMESTAMP_SIZE = Long.BYTES + Integer.BYTES;
	private static final int BYTE_ARRAY_SIZE = Integer.BYTES * 2 + TIMESTAMP_SIZE * 2;

	public TokenModel(int userId) {
		this.userId = userId;
	}

	private TokenModel(int tokenId, int userId, Timestamp createDate, Timestamp validBy) {
		this.tokenId = tokenId;
		this.userId = userId;
		this.createDate = createDate;
		this.validBy = validBy;
	}

	public int getTokenId() {
		return tokenId;
	}

	public int getUserId() {
		return userId;
	}

	public Timestamp getCreateDate() {
		return createDate;
	}

	public Timestamp getValid_by() {
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
		byte[] createDateBytes = toByteArray(createDate);
		System.arraycopy(createDateBytes, 0, result, Integer.BYTES * 2, TIMESTAMP_SIZE);
		byte[] validByBytes = toByteArray(validBy);
		System.arraycopy(validByBytes, 0, result, Integer.BYTES * 2 + TIMESTAMP_SIZE, TIMESTAMP_SIZE);

		return result;
	}

	public String serializeToString() {
		return Base64.getEncoder().encodeToString(this.serialize());
	}

	public static TokenModel deserialize(byte[] data) throws CipherErrorException {

		if (data.length != BYTE_ARRAY_SIZE) throw new IllegalArgumentException("Array length invalid");

		byte[] tokenBytes = new byte[Integer.BYTES];
		System.arraycopy(data, 0, tokenBytes, 0,  Integer.BYTES);
		int token = toInt(tokenBytes);
		byte[] userBytes = new byte[Integer.BYTES];
		System.arraycopy(data, Integer.BYTES, userBytes, 0,  Integer.BYTES);
		int user = toInt(userBytes);
		byte[] createDateBytes = new byte[TIMESTAMP_SIZE];
		System.arraycopy(data, Integer.BYTES * 2, createDateBytes, 0, TIMESTAMP_SIZE);
		Timestamp createDate = toTimeStamp(createDateBytes);
		byte[] validByBytes = new byte[TIMESTAMP_SIZE];
		System.arraycopy(data, Integer.BYTES * 2 + TIMESTAMP_SIZE, validByBytes, 0, TIMESTAMP_SIZE);
		Timestamp validBy = toTimeStamp(validByBytes);

		return new TokenModel(token, user, createDate, validBy);
	}

	public static TokenModel deserializeFromString(String data)
			throws IllegalArgumentException, CipherErrorException {
		return deserialize(Base64.getDecoder().decode(data));
	}
}