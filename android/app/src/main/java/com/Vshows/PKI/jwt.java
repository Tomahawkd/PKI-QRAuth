package com.Vshows.PKI;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.SecretKey;


public class jwt {



    Key key = Keys.secretKeyFor(SignatureAlgorithm.HS512);

    String jws = Jwts.builder().setSubject("Joe").signWith(key).compact();

    public Map<String,Object> getMyHeaderMap(){
        Map m = new HashMap();
        m.put("alg","HS512");
        return  m;
    }

    public Map<String,Object> getMyClaimMap(String username,String password){
        Map m = new HashMap();
        m.put("username",username);
        m.put("password",password);
        return  m;
    }

    public String init(){
        Map<String,Object> header = getMyHeaderMap();
        Map<String,Object> claim = getMyClaimMap("Vshows","123456");
        SecretKey key = Keys.secretKeyFor(SignatureAlgorithm.HS512); //or HS384 or HS512
        String jws = Jwts.builder()
                .setHeader(header)
                .setClaims(claim).signWith(key).compact();
        return jws;
    }

    public void read(String s){
        Jws<Claims> jws;
        jws = Jwts.parser()         // (1)
                .setSigningKey(key)         // (2)
                .parseClaimsJws(s);
        // (3)
        ;
    }

}
