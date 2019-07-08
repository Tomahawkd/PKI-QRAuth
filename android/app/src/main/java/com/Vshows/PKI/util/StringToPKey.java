package com.Vshows.PKI.util;

import android.util.Log;

import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import io.tomahawkd.pki.api.client.util.Utils;

public class StringToPKey {
    public static PublicKey getPublicKey(String pu){
        PublicKey a = null;
        try {
            X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(Utils.base64Decode(pu));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            a = keyFactory.generatePublic(x509EncodedKeySpec);
        } catch (Exception e){
            e.printStackTrace();
            Log.d("pubkeyerror",e.getMessage());
        }
        return a;
    }
    public static PrivateKey getPrivateKey(String pr){
        PrivateKey a = null;
        try {
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(Utils.base64Decode(pr));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            a =  keyFactory.generatePrivate(pkcs8EncodedKeySpec);
        } catch (Exception e){
            e.printStackTrace();
            Log.d("prikeyerror",e.getMessage());
        }
        return a;
    }
}
