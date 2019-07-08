package com.Vshows.PKI.util;

public class UserLog {
    private transient int userId;
    private transient int systemId;
    private String ip;
    private String device;
    private String message;

    public UserLog(int userId, int systemId, String ip, String device, String message) {
        this.userId = userId;
        this.systemId = systemId;
        this.ip = ip;
        this.device = device;
        this.message = message;
    }

    public int getUserId() {
        return userId;
    }

    public void setUserId(int userId) {
        this.userId = userId;
    }

    public int getSystemId() {
        return systemId;
    }

    public void setSystemId(int systemId) {
        this.systemId = systemId;
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
