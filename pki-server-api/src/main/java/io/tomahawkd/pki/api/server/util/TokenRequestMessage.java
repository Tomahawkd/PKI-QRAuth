package io.tomahawkd.pki.api.server.util;

import com.google.gson.Gson;
import com.google.gson.annotations.SerializedName;
import com.google.gson.reflect.TypeToken;

public class TokenRequestMessage<T> {

    @SerializedName("EToken")
    private String token;
    @SerializedName("T")
    private String time;
    @SerializedName("D")
    private String device;
    @SerializedName("M")
    private String message;

    public String getToken() {
        return token;
    }

    public String getTime() {
        return time;
    }

    public String getDevice() {
        return device;
    }

    public Message<T> getMessage() {
        return new Gson().fromJson(message, new TypeToken<Message<T>>() {
        }.getType());
    }

    public void setToken(String token) {
        this.token = token;
    }

    public void setTime(String time) {
        this.time = time;
    }

    public void setDevice(String device) {
        this.device = device;
    }

    public void setMessage(Message message) {
        this.message = new Gson().toJson(message);
    }

    public void setRawMessage(String message) {
        this.message = message;
    }

    public String toJson() {
        return new Gson().toJson(this);
    }

    public static <T> TokenRequestMessage<T> fromJson(String data) {
        return new Gson().fromJson(data, new TypeToken<TokenRequestMessage<T>>() {
        }.getType());
    }
}

