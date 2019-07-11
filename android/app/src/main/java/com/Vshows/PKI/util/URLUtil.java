package com.Vshows.PKI.util;

import android.content.Context;

import java.io.InputStream;
import java.util.Properties;

public class URLUtil {
    private static String URLFile = "URLconfig";

    public static String getTpubURL(Context context){
        Properties properties = new Properties();
        String url = null;

        try {
            properties.load(context.getAssets().open(URLFile));
            url = properties.getProperty("TPubURL");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return url;
    }

    public static String getSpubURL(Context context){
        Properties properties = new Properties();
        String url = null;

        try {
            properties.load(context.getAssets().open(URLFile));
            url = properties.getProperty("SPubURL");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return url;
    }

    public static String getLoginURL(Context context){
        Properties properties = new Properties();
        String url = null;

        try {
            properties.load(context.getAssets().open(URLFile));
            url = properties.getProperty("LoginURL");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return url;
    }

    public static String getRegisterURL(Context context){
        Properties properties = new Properties();
        String url = null;

        try {
            properties.load(context.getAssets().open(URLFile));
            url = properties.getProperty("RegisterURL");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return url;
    }

    public static String getSelfInfoURL(Context context){
        Properties properties = new Properties();
        String url = null;

        try {
            properties.load(context.getAssets().open(URLFile));
            url = properties.getProperty("SelfInfoURL");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return url;
    }

    public static String getChangeInfoURL(Context context){
        Properties properties = new Properties();
        String url = null;

        try {
            properties.load(context.getAssets().open(URLFile));
            url = properties.getProperty("ChangeInfoURL");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return url;
    }
    public static String getChangePasswordURL(Context context){
        Properties properties = new Properties();
        String url = null;

        try {
            properties.load(context.getAssets().open(URLFile));
            url = properties.getProperty("ChangePasswordURL");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return url;
    }
    public static String getGetLogURL(Context context){
        Properties properties = new Properties();
        String url = null;

        try {
            properties.load(context.getAssets().open(URLFile));
            url = properties.getProperty("GetLogURL");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return url;
    }
    public static String getGetTokenListURL(Context context){
        Properties properties = new Properties();
        String url = null;

        try {
            properties.load(context.getAssets().open(URLFile));
            url = properties.getProperty("GetTokenListURL");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return url;
    }
    public static String getRevokeTokenURL(Context context){
        Properties properties = new Properties();
        String url = null;

        try {
            properties.load(context.getAssets().open(URLFile));
            url = properties.getProperty("RevokeTokenURL");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return url;
    }
    public static String getReGenKeyURL(Context context){
        Properties properties = new Properties();
        String url = null;

        try {
            properties.load(context.getAssets().open(URLFile));
            url = properties.getProperty("ReGenKeyURL");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return url;
    }

    public static String getScanQRCodeURL(Context context){
        Properties properties = new Properties();
        String url = null;

        try {
            properties.load(context.getAssets().open(URLFile));
            url = properties.getProperty("ScanQRCodeURL");
        } catch (Exception e) {
            e.printStackTrace();
        }

        return url;
    }
}
