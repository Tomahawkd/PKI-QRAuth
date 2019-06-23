package com.Vshows.PKI;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import java.security.Key;


public class jwt {



    Key key = Keys.secretKeyFor(SignatureAlgorithm.HS256);

    String jws = Jwts.builder().setSubject("Joe").signWith(key).compact();

    public String init(){
        return jws;
    }

}
