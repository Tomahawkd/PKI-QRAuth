package io.tomahawkd.pki.model;

public class SystemLogModel {

    private int index;
    private String module;
    private int level;
    private String data;
    private String message;

    public static final int DEBUG = -1;
    public static final int OK = 0;
    public static final int LOW = 1;
    public static final int WARN = 2;
    public static final int FATAL = 3;

    public SystemLogModel(String module, int level,String message) {
        this.module = module;
        this.level = level;
        this.message = message;
    }

    public int getIndex() {
        return index;
    }

    public String getModule() {
        return module;
    }

    public int getLevel() { return level; }

    public String getData() {
        return data;
    }

    public String getMessage() {
        return message;
    }


    @Override
    public String toString() {
        return "{\"index\": \"" + index + "\",\"module\":\""+module+"\",\"level\": " + level + " ," +
                "\"data\":\"" + data + "\",\"message\":\"" + message + "\"}";
    }



}
