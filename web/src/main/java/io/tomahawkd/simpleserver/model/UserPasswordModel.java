package io.tomahawkd.simpleserver.model;

import com.google.gson.Gson;

public class UserPasswordModel {
    private int userid;
    private String username;
    private String password;

    public UserPasswordModel(String username,String password){
        this.username = username;
        this.password = password;
    }
    public UserPasswordModel(int userid ,String username,String password){
        this.userid=userid;
        this.username = username;
        this.password = password;
    }

    public int getIndex(){
        return userid;
    }

    public String getUsername(){
        return username;
    }

    public String getPassword(){
        return password;
    }

    public void setUserid(int userid) {
        this.userid = userid;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String toString(){
        return new Gson().toJson(this);    }
}
