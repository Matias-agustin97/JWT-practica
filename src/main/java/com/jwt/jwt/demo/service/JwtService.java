package com.jwt.jwt.demo.service;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.*;
import java.util.function.Function;

@Service
public class JwtService {

    //This is the key we will use to sign the jwt
    private static final String SECRET_KEY="HWuqPGLe5c30Bi6HQQwnyYAHrjvwGtJH";





    private Key getSignKey(){
        //This creates our key based on our secret_key string

        byte[] keyBytes= Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    //Our filter intercepts the request, if there is a jwt this function gets called extracting data from thetoken
    public String extractUserName(String token){

        return extractClaim(token,Claims::getSubject);//the subjet should be the email of the user, or user name
    }

    private <T> T extractClaim(String token, Function<Claims,T> claimResolver){
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }

    public String generateToken(Map<String, Object> extraClaims, UserDetails userDetails){

        return Jwts.builder()
                .setClaims(extraClaims)//We add data to the payload,as the subject claims should be the email, we get it with UserDetails
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*24*7))
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }
    
    public boolean isTokenValid(String token,UserDetails userDetails){
        final String username=extractUserName(token);

        //We check the username in the token is the same we have as input
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token,Claims::getExpiration);
    }


    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)//Parse the encrypted jtw payload
                .getBody();//With the token payload decrypted, we can read the claims
    }
}
