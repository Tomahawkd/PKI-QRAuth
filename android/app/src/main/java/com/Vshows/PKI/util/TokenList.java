package com.Vshows.PKI.util;

public class TokenList {
    private String ua;
    private String token;

    public TokenList(String ua,String token){
        this.ua = ua;
        this.token = token;
    }

    public String getUa() {
        return ua;
    }

    public String getToken() {
        return token;
    }

    public void setUa(String ua) {
        this.ua = ua;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
