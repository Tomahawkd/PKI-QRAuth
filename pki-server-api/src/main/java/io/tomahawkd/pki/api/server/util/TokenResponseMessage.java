package io.tomahawkd.pki.api.server.util;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import com.google.gson.reflect.TypeToken;

public class TokenResponseMessage<T> {

	@SerializedName("K")
	private String clientKey;
	@SerializedName("M")
	private String message;
	@SerializedName("T")
	private String time;
	@SerializedName("U")
	private String userTag;

	public String getClientKey() {
		return clientKey;
	}

	public Message<T> getMessage() {
		return new Gson().fromJson(message, new TypeToken<Message<T>>() {
		}.getType());
	}

	public String getTime() {
		return time;
	}

	public String getUserTag() {
		return userTag;
	}

	public void setClientKey(String clientKey) {
		this.clientKey = clientKey;
	}

	public void setMessage(Message message) {
		this.message = new Gson().toJson(message);
	}

	public void setTime(String time) {
		this.time = time;
	}

	public void setUserTag(String userTag) {
		this.userTag = userTag;
	}

	public String toJson() {
		return new Gson().toJson(this);
	}

	public static <T> TokenResponseMessage<T> fromJson(String data) {
		return new Gson().fromJson(data, new TypeToken<TokenResponseMessage<T>>() {
		}.getType());
	}
}
