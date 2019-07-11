package io.tomahawkd.pki.util;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

public class Message<T> {

	private int status;
	private T message;

	public Message() {
		this.status = -1;
		this.message = null;
	}

	public Message(int status, T message) {
		this.status = status;
		this.message = message;
	}

	public Message<T> setStatus(int status) {
		this.status = status;
		return this;
	}

	public Message<T> setOK() {
		this.status = 0;
		return this;
	}

	public Message<T> setError() {
		this.status = 1;
		return this;
	}

	public Message<T> setMessage(T message) {
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

	public static <T> Message<T> fromJson(String json) {
		return new Gson().fromJson(json, new TypeToken<Message<T>>(){}.getType());
	}
}
