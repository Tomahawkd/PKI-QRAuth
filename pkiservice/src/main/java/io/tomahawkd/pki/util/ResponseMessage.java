package io.tomahawkd.pki.util;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

public class ResponseMessage<T> {

	private int status;
	private T message;

	public ResponseMessage() {
		this.status = -1;
		this.message = null;
	}

	public ResponseMessage(int status, T message) {
		this.status = status;
		this.message = message;
	}

	public ResponseMessage<T> setOK() {
		this.status = 0;
		return this;
	}

	public ResponseMessage<T> setError() {
		this.status = 1;
		return this;
	}

	public ResponseMessage<T> setMessage(T message) {
		this.message = message;
		return this;
	}

	public boolean isOk() {
		return status == 0;
	}

	public boolean isError() {
		return status == 1;
	}

	public int getStatus() {
		return status;
	}

	public T getMessage() {
		return message;
	}

	public String toJson() {
		return new Gson().toJson(this);
	}

	public static <T> ResponseMessage<T> fromJson(String json) {
		return new Gson().fromJson(json, new TypeToken<ResponseMessage<T>>(){}.getType());
	}
}
