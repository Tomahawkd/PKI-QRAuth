package com.Vshows.PKI.util;

public class TokenList {
    private String date;
    private String ip;
    private String device;
    private String ID;

    public TokenList(String date,String ip,String device,String id){
        this.date = date;
        this.ip = ip;
        this.device = device;
        this.ID = id;
    }

    public String getDate() {
        return date;
    }

    public String getDevice() {
        return device;
    }

    public String getID() {
        return ID;
    }

    public String getIp() {
        return ip;
    }
}
