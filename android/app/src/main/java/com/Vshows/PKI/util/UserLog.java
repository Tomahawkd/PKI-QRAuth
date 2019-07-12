package com.Vshows.PKI.util;

public class UserLog {
    private String time;
    private String ip;
    private String device;
    private String message;

    public UserLog(String time, String ip, String device, String message) {
        this.time = time;
        this.ip = ip;
        this.device = device;
        this.message = message;
    }

    public String getTime() {
        return time;
    }

    public String getIp() {
        return ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public String getDevice() {
        return device;
    }

    public void setDevice(String device) {
        this.device = device;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
