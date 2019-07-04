package io.tomahawkd.pki.model;

import java.sql.Timestamp;

public class QrStatusModel {

	private Integer tokenId;
	private int nonce;
	private String symKey;
	private String iv;
	private int status;
	private Timestamp validBy;

	public QrStatusModel(int nonce, String symKey, String iv) {
		this(null, nonce, symKey, iv, 0, null);
	}

	private QrStatusModel(Integer tokenId, int nonce, String symKey, String iv, int status, Timestamp validBy) {
		this.tokenId = tokenId;
		this.nonce = nonce;
		this.symKey = symKey;
		this.iv = iv;
		this.status = status;
		this.validBy = validBy;
	}

	public int getTokenId() {
		return tokenId;
	}

	public int getNonce() {
		return nonce;
	}

	public String getSymKey() {
		return symKey;
	}

	public String getIv() {
		return iv;
	}

	public int getStatus() {
		return status;
	}

	public Timestamp getValidBy() {
		return validBy;
	}
}
