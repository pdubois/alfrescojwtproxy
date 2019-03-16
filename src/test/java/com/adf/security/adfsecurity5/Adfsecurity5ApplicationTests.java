package com.adf.security.adfsecurity5;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.security.Key;
import java.util.Base64;
import java.util.Date;

import javax.crypto.spec.SecretKeySpec;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.xml.bind.DatatypeConverter;

import org.apache.http.HttpStatus;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.bind.RelaxedPropertyResolver;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockFilterConfig;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.junit4.SpringRunner;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.lang.Assert;

@RunWith(SpringRunner.class)
@SpringBootTest
public class Adfsecurity5ApplicationTests
{

    @Autowired Environment environment;
    
    //property resolver with proxy.alfresco root
    private RelaxedPropertyResolver propertyResolver;
    private String secret;
    //jwt Base64 encoded
    private String jwt;
    
    @Before
    public void setUp() {
        propertyResolver = new RelaxedPropertyResolver(environment, "proxy.alfresco.");
        secret = propertyResolver.getProperty("secret");
        jwt = createJWTEncodedB64("123", "admin@app.activiti.com", "signature", 1000 * 3600 * 500, secret);
    }

    @Test
    public void createDecodeToken()
    {
        propertyResolver = new RelaxedPropertyResolver(environment, "proxy.alfresco.");
        String secret = propertyResolver.getProperty("secret");
        AdfsecurityFilter jwtFilter = new AdfsecurityFilter();
        String token = jwtFilter.createJWT("123", "admin@app.activiti.com", "signature", 1000 * 3600, secret);

        // System.out.println("|" + token + "|");

        Claims claims = parseJWT(token, secret);

        Assert.isTrue(claims.getId().equals("123"));
        Assert.isTrue(claims.getIssuer().equals("admin@app.activiti.com"));
        Assert.isTrue(claims.getSubject().equals("signature"));
    }

    @Test
    public void createDecodeTokenBase64()
    {
        propertyResolver = new RelaxedPropertyResolver(environment, "proxy.alfresco.");
        String secret = propertyResolver.getProperty("secret");
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
        AdfsecurityFilter jwtFilter = new AdfsecurityFilter();
        return jwtFilter.createJWTEncodedB64(id, issuer, subject, ttlMillis, secret);
        // Encode data on your side using BASE64
//        byte[] bytesEncoded = Base64.getEncoder().encode(createJWT(id, issuer, subject, ttlMillis, secret).getBytes());
//        return new String(bytesEncoded).replaceAll("=+$", "");

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
    
    /**
     * Test in pass thought mode
     * test using alf_ticket
     * @throws Exception
     */
    @Test
    public void testPassThrought() throws Exception {
        MockFilterConfig filterConfig = new MockFilterConfig();
        
        filterConfig.addInitParameter("secret", propertyResolver.getProperty("secret"));
        filterConfig.addInitParameter("passthrough", "true");
        
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        AdfsecurityFilter jwtFilter = new AdfsecurityFilter();
        
        jwtFilter.init(filterConfig);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRequestURI("/alfresco/api/-default-/public/authentication/versions/1/tickets");
        request.setPathInfo("/alfresco/api/-default-/public/authentication/versions/1/tickets");
        request.setMethod("GET");
        jwtFilter.doFilter(request, response, filterChain);
        assertThat(response.getStatus()).isEqualTo(200);
    }
    
    /**
     * Test that then when not in passthought mode a ticket can not be obtained
     * test using alf_ticket
     * @throws Exception
     */
    @Test
    public void testPassThroughtNoticket() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        //request.addHeader(JWTConfigurer.AUTHORIZATION_HEADER, "Bearer " + jwt);
        request.setRequestURI("/alfresco/api/-default-/public/authentication/versions/1/tickets");
        request.setPathInfo("/alfresco/api/-default-/public/authentication/versions/1/tickets");
        request.setMethod("POST");
        String requestPayload = "{\"userId\": \"admin@app.activiti.com\", \"password\": \"" + jwt + "\"}";
        
        request.setContent(requestPayload.getBytes());
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        AdfsecurityFilter jwtFilter = new AdfsecurityFilter();
        
        MockFilterConfig filterConfig = new MockFilterConfig();
        
        filterConfig.addInitParameter("secret", propertyResolver.getProperty("secret"));
        filterConfig.addInitParameter("passthrough", propertyResolver.getProperty("passthrough"));
        
        jwtFilter.init(filterConfig);
        jwtFilter.doFilter(request, response, filterChain);
        assertThat(response.getStatus()).isEqualTo(200);
        //test that answer is correct
        String resBody = new String(response.getContentAsByteArray());
        ObjectMapper mapper = new ObjectMapper();
        JsonNode theJsonBody = mapper.readTree(resBody);
        //out.print("{\"entry\":{\"id\":\"" + uniqueKey + "\",\"userId\":\"" + issuer + "\"}}");
        String issuer = theJsonBody.get("entry").get("userId") + "";
        String authorisation = theJsonBody.get("entry").get("id") + "";
        //remove quotes from authorization
        authorisation = authorisation.replaceAll("\"", "");
        assertThat(issuer.equals("admin@app.activiti.com"));
        
 
        //---------------------------------------------------
        //position a Authorization header test that is authorized
        response = new MockHttpServletResponse();
        response.setStatus(200);
        
        request = new MockHttpServletRequest();
        
        request.setRequestURI("/alfresco/api/-default-/public/test");
        request.setPathInfo("/alfresco/api/-default-/public/test");
        request.setMethod("GET");
        
        byte[] authorizationByteEncoded = Base64.getEncoder().encode(("id:" + authorisation).getBytes());
        String encodedTicket = new String(authorizationByteEncoded);
        request.addHeader("Authorization", "Basic " +encodedTicket);
        
        jwtFilter.doFilter(request, response, filterChain);
        //header positionned
        assertThat(response.getStatus()).isEqualTo(200);
        
        //---------------------------------------------------
        ///alfresco/api/-default-/public/authentication/versions/1/tickets
        //test that can not get a ticket even if authenticated
        response = new MockHttpServletResponse();
        response.setStatus(200);
        
        request = new MockHttpServletRequest();
        
        request.setRequestURI("/alfresco/api/-default-/public/authentication/versions/1/tickets");
        request.setPathInfo("/alfresco/api/-default-/public/authentication/versions/1/tickets");
        request.setMethod("POST");
        requestPayload = "{\"userId\": \"admin@app.activiti.com\", \"password\": \"" + jwt + "\"}";
        
        request.setContent(requestPayload.getBytes());
        
        authorizationByteEncoded = Base64.getEncoder().encode(("id:" + authorisation).getBytes());
        encodedTicket = new String(authorizationByteEncoded);
        request.addHeader("Authorization", "Basic " +encodedTicket);
        
        jwtFilter.doFilter(request, response, filterChain);
        //header positionned
        assertThat(response.getStatus()).isEqualTo(403);
        
        //---------------------------------------------------
        //test that forbidden if claimed user is admin@app.activiti.com and admin2@app.activiti.com
        //is positionned in the post request. They must be identical
        response = new MockHttpServletResponse();
        response.setStatus(200);
        
        request = new MockHttpServletRequest();
        
        request.setRequestURI("/alfresco/api/-default-/public/authentication/versions/1/tickets");
        request.setPathInfo("/alfresco/api/-default-/public/authentication/versions/1/tickets");
        request.setMethod("POST");
        requestPayload = "{\"userId\": \"admin2@app.activiti.com\", \"password\": \"" + jwt + "\"}";
        
        request.setContent(requestPayload.getBytes());
        
        authorizationByteEncoded = Base64.getEncoder().encode(("id:" + authorisation).getBytes());
        //encodedTicket = new String(authorizationByteEncoded);
        //request.addHeader("Authorization", "Basic " +encodedTicket);
        
        jwtFilter.doFilter(request, response, filterChain);
        //header positionned
        assertThat(response.getStatus()).isEqualTo(403);
        

  
    }

    /**
     * Test login, request after log in, test with credential in AUTHORITY header
     * test using alf_ticket
     * @throws Exception
     */
    @Test
    public void testJWTFilter() throws Exception {
       
        MockHttpServletRequest request = new MockHttpServletRequest();
        //request.addHeader(JWTConfigurer.AUTHORIZATION_HEADER, "Bearer " + jwt);
        request.setRequestURI("/alfresco/api/-default-/public/authentication/versions/1/tickets");
        request.setPathInfo("/alfresco/api/-default-/public/authentication/versions/1/tickets");
        request.setMethod("POST");
        String requestPayload = "{\"userId\": \"admin@app.activiti.com\", \"password\": \"" + jwt + "\"}";
        
        request.setContent(requestPayload.getBytes());
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        AdfsecurityFilter jwtFilter = new AdfsecurityFilter();
        
        MockFilterConfig filterConfig = new MockFilterConfig();
        
        filterConfig.addInitParameter("secret", propertyResolver.getProperty("secret"));
        filterConfig.addInitParameter("passthrough", propertyResolver.getProperty("passthrough"));
        
        jwtFilter.init(filterConfig);
        jwtFilter.doFilter(request, response, filterChain);
        assertThat(response.getStatus()).isEqualTo(200);
        //test that answer is correct
        String resBody = new String(response.getContentAsByteArray());
        ObjectMapper mapper = new ObjectMapper();
        JsonNode theJsonBody = mapper.readTree(resBody);
        //out.print("{\"entry\":{\"id\":\"" + uniqueKey + "\",\"userId\":\"" + issuer + "\"}}");
        String issuer = theJsonBody.get("entry").get("userId") + "";
        String authorisation = theJsonBody.get("entry").get("id") + "";
        //remove quotes from authorization
        authorisation = authorisation.replaceAll("\"", "");
        assertThat(issuer.equals("admin@app.activiti.com"));
        
        //----------------------------------------------
        //check that can not access when not logged in
        response = new MockHttpServletResponse();
        response.setStatus(200);
        
        request = new MockHttpServletRequest();
        
        request.setRequestURI("/alfresco/api/-default-/public/test");
        request.setPathInfo("/alfresco/api/-default-/public/test");
        request.setMethod("GET");
        
        jwtFilter.doFilter(request, response, filterChain);
        //no header positionned
        assertThat(response.getStatus()).isEqualTo(403);
        
        //---------------------------------------------------
        //position a Authorization header test that authorized
        response = new MockHttpServletResponse();
        response.setStatus(200);
        
        request = new MockHttpServletRequest();
        
        request.setRequestURI("/alfresco/api/-default-/public/test");
        request.setPathInfo("/alfresco/api/-default-/public/test");
        request.setMethod("GET");
        
        byte[] authorizationByteEncoded = Base64.getEncoder().encode(("id:" + authorisation).getBytes());
        String encodedTicket = new String(authorizationByteEncoded);
        request.addHeader("Authorization", "Basic " +encodedTicket);
        
        jwtFilter.doFilter(request, response, filterChain);
        //header positionned
        assertThat(response.getStatus()).isEqualTo(200);
        
        //---------------------------------------------------------------
        // test that authorization is given if using alf_ticket
        // as authorization bearer
        request = new MockHttpServletRequest();
        
        request.setRequestURI("/alfresco/api/-default-/public/test");
        request.setPathInfo("/alfresco/api/-default-/public/test");
        request.setMethod("GET");
        request.addParameter("alf_ticket", authorisation);
        
        response.setStatus(200);
        
        jwtFilter = new AdfsecurityFilter();
        
        filterConfig = new MockFilterConfig();
        
        filterConfig.addInitParameter("secret", propertyResolver.getProperty("secret"));
        filterConfig.addInitParameter("passthrough", propertyResolver.getProperty("passthrough"));
        
        jwtFilter.init(filterConfig);
        filterChain = new MockFilterChain();
        jwtFilter.doFilter(request, response, filterChain);
        //header positionned
        assertThat(response.getStatus()).isEqualTo(200);
        
 
        
    }
    

    
    
    /**
     * test that we got a 403 forbidden after log out
     * @throws Exception
     */
    @Test
    public void testLogOut() throws Exception {
        
        //------------------------------------------------------
        // Log in
        MockHttpServletRequest request = new MockHttpServletRequest();
        //request.addHeader(JWTConfigurer.AUTHORIZATION_HEADER, "Bearer " + jwt);
        request.setRequestURI("/alfresco/api/-default-/public/authentication/versions/1/tickets");
        request.setPathInfo("/alfresco/api/-default-/public/authentication/versions/1/tickets");
        request.setMethod("POST");
        String requestPayload = "{\"userId\": \"admin@app.activiti.com\", \"password\": \"" + jwt + "\"}";
        
        request.setContent(requestPayload.getBytes());
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain filterChain = new MockFilterChain();
        AdfsecurityFilter jwtFilter = new AdfsecurityFilter();
        
        MockFilterConfig filterConfig = new MockFilterConfig();
        
        filterConfig.addInitParameter("secret", propertyResolver.getProperty("secret"));
        filterConfig.addInitParameter("passthrough", propertyResolver.getProperty("passthrough"));
        
        jwtFilter.init(filterConfig);
        jwtFilter.doFilter(request, response, filterChain);
        assertThat(response.getStatus()).isEqualTo(200);
        //test that answer is correct
        String resBody = new String(response.getContentAsByteArray());
        ObjectMapper mapper = new ObjectMapper();
        JsonNode theJsonBody = mapper.readTree(resBody);
        //out.print("{\"entry\":{\"id\":\"" + uniqueKey + "\",\"userId\":\"" + issuer + "\"}}");
        String issuer = theJsonBody.get("entry").get("userId") + "";
        String authorisation = theJsonBody.get("entry").get("id") + "";
        //remove quotes from authorization
        authorisation = authorisation.replaceAll("\"", "");
        assertThat(issuer.equals("admin@app.activiti.com"));
        
        //------------------------------------------
        //test that we can access after log in
        //position a Authorization header test that authorized
        response = new MockHttpServletResponse();
        response.setStatus(200);
        
        request = new MockHttpServletRequest();
        
        request.setRequestURI("/alfresco/api/-default-/public/test");
        request.setPathInfo("/alfresco/api/-default-/public/test");
        request.setMethod("GET");
        
        byte[] authorizationByteEncoded = Base64.getEncoder().encode(("id:" + authorisation).getBytes());
        String encodedTicket = new String(authorizationByteEncoded);
        request.addHeader("Authorization", "Basic " +encodedTicket);
        
        jwtFilter.doFilter(request, response, filterChain);
        //header positionned
        assertThat(response.getStatus()).isEqualTo(200);
        
        //---------------------------------------------
        // send a log out
        request = new MockHttpServletRequest();
        
        request.setRequestURI("/alfresco/api/-default-/public/authentication/versions/1/tickets/-me-");
        request.setPathInfo("/alfresco/api/-default-/public/authentication/versions/1/tickets/-me-");
        request.setMethod("DELETE");
        request.addHeader("Authorization", "Basic " +encodedTicket);
        
        response.setStatus(200);
        
        jwtFilter = new AdfsecurityFilter();
        
        filterConfig = new MockFilterConfig();
        
        filterConfig.addInitParameter("secret", propertyResolver.getProperty("secret"));
        filterConfig.addInitParameter("passthrough", propertyResolver.getProperty("passthrough"));
        
        jwtFilter.init(filterConfig);
        filterChain = new MockFilterChain();
        jwtFilter.doFilter(request, response, filterChain);
        //header positionned
        //status no content
        assertThat(response.getStatus()).isEqualTo(204);
        

        //----------------------------------------------
        //try to access expect to get a 403 forbidden
        //check that can not access when not logged in
        response = new MockHttpServletResponse();
        response.setStatus(200);
        
        request = new MockHttpServletRequest();
        
        request.setRequestURI("/alfresco/api/-default-/public/test");
        request.setPathInfo("/alfresco/api/-default-/public/test");
        request.setMethod("GET");
        request.addHeader("Authorization", "Basic " +encodedTicket);
        filterChain = new MockFilterChain();
        jwtFilter.doFilter(request, response, filterChain);
        //no header positioned
        assertThat(response.getStatus()).isEqualTo(403);
        
        //-----------------------------------------------------
        //also test can not access using alf_ticket
        // test that authorization is given if using alf_ticket
        // as authorization bearer
        request = new MockHttpServletRequest();
        
        request.setRequestURI("/alfresco/api/-default-/public/test");
        request.setPathInfo("/alfresco/api/-default-/public/test");
        request.setMethod("GET");
        request.addParameter("alf_ticket", authorisation);
        
        response = new MockHttpServletResponse();
        response.setStatus(200);
        
        jwtFilter = new AdfsecurityFilter();
        
        filterConfig = new MockFilterConfig();
        
        filterConfig.addInitParameter("secret", propertyResolver.getProperty("secret"));
        filterConfig.addInitParameter("passthrough", propertyResolver.getProperty("passthrough"));
        
        jwtFilter.init(filterConfig);
        filterChain = new MockFilterChain();
        jwtFilter.doFilter(request, response, filterChain);
        assertThat(response.getStatus()).isEqualTo(403);
        
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
