package com.adf.security.adfsecurity5;

import java.security.Key;
import java.util.Base64;
import java.util.Date;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.lang.Assert;

@RunWith(SpringRunner.class)
@SpringBootTest
public class Adfsecurity5ApplicationTests
{

    @Test
    public void contextLoads()
    {
    }

    @Test
    public void createDecodeToken()
    {

        String secret = "This is secret";
        String token = createJWT("123", "admin@app.activiti.com", "signature", 1000 * 3600, secret);

        // System.out.println("|" + token + "|");

        Claims claims = parseJWT(token, secret);

        Assert.isTrue(claims.getId().equals("123"));
        Assert.isTrue(claims.getIssuer().equals("admin@app.activiti.com"));
        Assert.isTrue(claims.getSubject().equals("signature"));
    }

    @Test
    public void createDecodeTokenBase64()
    {

        String secret = "This is secret";
        String token = createJWTEncodedB64("123", "test@app.activiti.com", "signature", 1000 * 3600 * 24 * 1000, secret);

        System.out.println("test@app.activiti.com: |" + token + "|");

        Claims claims = parseJWTEncodedB64(token, secret);

        Assert.isTrue(claims.getId().equals("123"));
        Assert.isTrue(claims.getIssuer().equals("test@app.activiti.com"));
        Assert.isTrue(claims.getSubject().equals("signature"));

        //-----------------------------------------------------------------------------------------
        token = createJWTEncodedB64("123", "admin@app.activiti.com", "signature", 1000 * 3600 * 500, secret);

        System.out.println("admin@app.activiti.com: |" + token + "|");

        claims = parseJWTEncodedB64(token, secret);

        Assert.isTrue(claims.getId().equals("123"));
        Assert.isTrue(claims.getIssuer().equals("admin@app.activiti.com"));
        Assert.isTrue(claims.getSubject().equals("signature"));
    }

    private String createJWTEncodedB64(String id, String issuer, String subject, long ttlMillis, String secret)
    {
        // Encode data on your side using BASE64
        byte[] bytesEncoded = Base64.getEncoder().encode(createJWT(id, issuer, subject, ttlMillis, secret).getBytes());
        return new String(bytesEncoded);

    }

    // Sample method to construct a JWT
    private String createJWT(String id, String issuer, String subject, long ttlMillis, String secret)
    {

        // The JWT signature algorithm we will be using to sign the token
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);

        // We will sign our JWT with our ApiKey secret
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(secret);
        Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());

        // Let's set the JWT Claims
        JwtBuilder builder = Jwts.builder().setId(id).setIssuedAt(now).setSubject(subject).setIssuer(issuer)
                .signWith(signatureAlgorithm, signingKey);

        // if it has been specified, let's add the expiration
        if (ttlMillis >= 0)
        {
            long expMillis = nowMillis + ttlMillis;
            Date exp = new Date(expMillis);
            builder.setExpiration(exp);
        }

        // Builds the JWT and serializes it to a compact, URL-safe string
        return builder.compact();
    }

    // Sample method to validate and read the JWT encoded in base 64
    private Claims parseJWTEncodedB64(String jwtBase64, String secret)
    {

        byte[] decodedBytes = Base64.getDecoder().decode(jwtBase64);
        String jwt = new String(decodedBytes);

        return parseJWT(jwt, secret);
    }

    // Sample method to validate and read the JWT
    private Claims parseJWT(String jwt, String secret)
    {

        // This line will throw an exception if it is not a signed JWS (as expected)
        Claims claims = Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(secret)).parseClaimsJws(jwt)
                .getBody();

        return claims;
    }
}
