package io.tomahawkd.pki.model;

public class UserPasswordModel {
    private int index;
    private String username;
    private String password;

    public UserPasswordModel(int index,String username,String password){
        this.index = index;
        this.username = username;
        this.password = password;
    }

    public int getIndex(){
        return index;
    }

    public String getUsername(){
        return username;
    }

    public String getPassword(){
        return password;
    }

    public String toString(){
        return "{\"index\":" + index + ",\"username\":\"" + username + "\",\"password\":\"" + password + "\"}";
    }
}
