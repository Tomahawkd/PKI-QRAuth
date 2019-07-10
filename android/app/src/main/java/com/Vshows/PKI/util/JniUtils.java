package com.Vshows.PKI.util;
import android.util.Log;

import java.io.UnsupportedEncodingException;
import java.lang.annotation.Native;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import io.tomahawkd.pki.api.client.exceptions.CipherErrorException;
import io.tomahawkd.pki.api.client.util.SecurityFunctions;

/**
 * Created by xy on 16/1/4.
 */
public class JniUtils {

    public native static byte[] getKeyValue();
    public native static byte[] getIv();
    // 0 : sucess  1: fail
    public native static int checkSign(Object object);

    private static byte[]keyValue;
    private static byte[]iv;






    static {
        System.loadLibrary("jni-aes");
        keyValue = getKeyValue();
        iv = getIv();
        try {
            Log.d("keyValue", new String(keyValue,"UTF-8"));
            Log.d("Iv", new String(iv,"UTF-8"));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        if (null != keyValue && null != iv) {
            Log.d("hh", "a");

        }
    }





    public static String encode(String msg) throws CipherErrorException, UnsupportedEncodingException {

        byte[] result = SecurityFunctions.encryptSymmetric(keyValue,iv,msg.getBytes("ISO8859-1"));
        return new String(result,"ISO8859-1");
    }

    public static String decode(String value) throws CipherErrorException, UnsupportedEncodingException {
       byte[] result = SecurityFunctions.decryptSymmetric(keyValue,iv,value.getBytes("ISO8859-1"));
        return new String(result,"ISO8859-1");
    }



}