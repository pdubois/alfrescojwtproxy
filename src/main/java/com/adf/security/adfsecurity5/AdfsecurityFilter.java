package com.adf.security.adfsecurity5;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.security.Key;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Random;
import java.util.UUID;
import java.util.Vector;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import javax.crypto.spec.SecretKeySpec;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;

import org.junit.Assert;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.DelegatingServletInputStream;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class AdfsecurityFilter implements Filter
{

    private FilterConfig filterConfig = null;

    private static final Logger logger = LoggerFactory.getLogger(AdfsecurityFilter.class);

    private static ThreadLocal<Random> random = new ThreadLocal<Random>()
    {
        @Override
        protected Random initialValue()
        {
            return new Random(System.currentTimeMillis() * Thread.currentThread().getId());
        }
    };

    private static Map<String, String> ticketMap = new ConcurrentHashMap<String, String>();

    @Override
    public void destroy()
    {

    }

    /**
     * Manages the logout request
     * 
     * @param req
     * @param response
     * @param chain
     */
    private void manageLogout(HttpServletRequest req, ServletResponse response, FilterChain chain)
    {
        // try to logout
        HeaderMapRequestWrapper requestWrapper = new HeaderMapRequestWrapper(req, false);
        HttpServletResponse responseOK = (HttpServletResponse) response;

        // trying yo dry ticket from header or alf_ticket
        String headerSet = Optional.ofNullable(setHeaderFromAuthorizationHeader(requestWrapper))
                .orElse(setHeaderFromAlfTicket(requestWrapper));

        String alfTicket = null;
        if (headerSet != null && !headerSet.isEmpty())
        {
            String authorization = requestWrapper.getHeader("Authorization");

            if (authorization != null && !authorization.isEmpty())
            {
                // get second part of it, skip Basic<space>
                String parts[] = authorization.split(" ");
                if (parts != null && parts.length > 1)
                {
                    // decode the base 64 because it is encoded twice in base 64
                    byte[] decodedBytes = Base64.getDecoder().decode(parts[1]);
                    String jwtStill = new String(decodedBytes);

                    String partsToken[] = jwtStill.split(":");
                    if (partsToken != null && partsToken.length > 1)
                    {

                        // try to find the ticket in the map
                        alfTicket = partsToken[1];

                    }
                }

            }
        }

        // looking for remote user and delete it
        if (alfTicket != null)
            ticketMap.compute(alfTicket, (s, o) -> null);

        // status no content
        responseOK.setStatus(204);

        return;
    }

    protected void returnUnauthorized(ServletResponse response) throws IOException, ServletException
    {
        // unauthorized
        logger.info("+-+-+-+-+-+-+ unauthorized returned because Authorization or ALF_TICKET not present or not valid");
        ((HttpServletResponse) response).sendError(403);
        // return an error unauthorized
        String error = "{\"error\":{\"errorKey\":\"Login failed\",\"statusCode\":403,\"briefSummary\":\"01110880 Login failed\",\""
                + "\"stackTrace\":\"Pour des raisons de sécurité, le traçage de la pile n'est plus affiché, mais la propriété est conservée dans les versions précédente\","
                + "\"descriptionURL\":\"https://api-explorer.alfresco.com\"}}";

        PrintWriter out = response.getWriter();
        // send back the login error
        out.print(error);
        out.flush();

        return;
    }

    /**
     * This manages POST
     * /alfresco/api/-default-/public/authentication/versions/1/tickets to create
     * tickets DELETE
     * /alfresco/api/-default-/public/authentication/versions/1/tickets/-me- for
     * logout
     * 
     * It sets the "X-Alfresco-Remote-User" for other requests. Alfresco must be
     * configured in pass through (see
     * :http://docs.alfresco.com/6.0/concepts/auth-passthru-intro.html ) Once the
     * JWT tohen authenticated, a ticket is generated by the filter an put in
     * "ticketMap". Key is the ticket, claimed identity is stored a a value. On
     * ervrty request, the ticket (identity) is transferred by the UI (ADF) and
     * validated against the HTABLE. If found "X-Alfresco-Remote-User" is set.
     * Ticket can be transferred using "ALF_TICKET" parameter or "Authorization"
     * header.
     * 
     * It can be set in in passthrough mode setting "passthrough" parameter in
     * config file. DO NOT FORGET to protect your Alfresco by setting up firewall.
     */
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException
    {
        int ran = random.get().nextInt(100000);
        logger.info("Entering doFilter (" + ran + ")");

        Assert.assertTrue(request != null && response != null && chain != null);

        String passthrough = this.filterConfig.getInitParameter("passthrough");

        if (passthrough.equals("true"))
        {
            // passthrough mode
            if (logger.isDebugEnabled())
            {
                logger.debug("--------In passthrough mode");
            }
            chain.doFilter(request, response); // Goes to default servlet.
            logger.info("Exit doFilter" + " (" + ran + ")");
            return;

        }

        if (request instanceof HttpServletRequest)
        {

            HttpServletRequest req = (HttpServletRequest) request;

            if (logger.isDebugEnabled())
            {
                logger.debug("--------In AdfsecurityFilter: " + req.getPathInfo() + " (" + ran + ")");
                logger.debug("--------Authorization: " + req.getHeader("Authorization") + " (" + ran + ")");
                Map<Object, String[]> params = Collections.list(req.getParameterNames()).stream()
                        .collect(Collectors.toMap(parameterName -> parameterName, req::getParameterValues));

                logger.debug("--------alf_ticket: "
                        + (params.get("alf_ticket") != null ? params.get("alf_ticket")[0] : "null"));
            }

            String pathInfo = req.getPathInfo();
            // /alfresco/api/-default-/public/authentication/versions/1/tickets/-me-
            if (pathInfo.startsWith("/alfresco/api/-default-/public/authentication/versions/1/tickets/-me-")
                    && req.getMethod().equalsIgnoreCase("DELETE"))
            {
                // this is a logout request
                manageLogout(req, response, chain);
                logger.info("Exit doFilter (" + ran + ")");
                return;
            }

            // check if trying to get a ticket by checking the following url:
            // /alfresco/api/-default-/public/authentication/versions/1/tickets
            if (pathInfo.startsWith("/alfresco/api/-default-/public/authentication/versions/1/tickets")
                    && req.getMethod().equalsIgnoreCase("POST"))
            {

                // this under is done for 2 reasons:
                // HEADERS can not be added directly on the request
                // and BODY can only be read once this is why
                // peek body is set to true
                HeaderMapRequestWrapper requestWrapper = new HeaderMapRequestWrapper(req, true);

                String loggedInUser = getHeaderFromAuthorizationHeader(requestWrapper);
                if (loggedInUser != null && !loggedInUser.isEmpty())
                {
                    returnUnauthorized(response);
                    logger.info("Exit doFilter (" + ran + ")");

                    return;
                }

                if (logger.isDebugEnabled())
                {
                    logger.debug("In AdfsecurityFilter: " + req.getPathInfo() + " (" + ran + ")");
                    logger.debug("In AdfsecurityFilter password: " + req.getParameter("password") + " (" + ran + ")");
                }

                String bodyString = new String(requestWrapper.getStoredBody());

                if (logger.isDebugEnabled())
                {
                    logger.debug("In AdfsecurityFilter BODY: " + bodyString);
                }

                ObjectMapper mapper = new ObjectMapper();
                JsonNode theJsonBody = mapper.readTree(bodyString);

                String passwordJwt = "" + theJsonBody.get("password");
                if (logger.isDebugEnabled())
                {
                    logger.debug("The Claimed user is: " + theJsonBody.get("userId").toString());
                    logger.debug("The JWT token is: " + theJsonBody.get("password"));
                    logger.debug("The passwordJwt is: " + passwordJwt);
                }

                // remove first and last "
                passwordJwt = passwordJwt.replaceAll("\"", "");
                Claims claims = null;
                try
                {
                    claims = parseJWTEncodedB64(passwordJwt, this.filterConfig.getInitParameter("secret"));
                    String userInBody = theJsonBody.get("userId") + "";
                    userInBody = userInBody.replaceAll("\"", "");
                    // test that the JWT token claimed user is same as userId
                    if (!userInBody.equals(claims.getIssuer()))
                    {
                        if (logger.isDebugEnabled())
                        {
                            logger.debug("+-+-+- userId " + userInBody + " different from " + claims.getIssuer());

                        }
                        throw new Exception("uid of the claim " + claims.getIssuer()
                                + " not equal to userId of the json body" + userInBody);
                    }
                } catch (Throwable e)
                {

                    returnUnauthorized(response);
                    logger.info("jwt token can not be trusted because: ", e);
                    logger.info("Exit doFilter (" + ran + ")");

                    return;
                }

                if (logger.isDebugEnabled())
                {
                    logger.debug("The positionned user is: " + claims.getIssuer());
                }

                // Do here the JWT checking/verification
                // if All OK then
                requestWrapper.addHeader("X-Alfresco-Remote-User", claims.getIssuer());

                // set the headers
                requestWrapper.addHeader("Access-Control-Allow-Origin", "*");
                requestWrapper.addHeader("cache-control", "no-cache");
                requestWrapper.addHeader("connection", "close");
                requestWrapper.addHeader("content-type", "application/json;charset=UTF-8");
                requestWrapper.addHeader("pragma", "no-cache");

                PrintWriter out = response.getWriter();
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");

                // issuer contains the user
                String issuer = claims.getIssuer();

                // generate ticket
                UUID uniqueKey = UUID.randomUUID();

                ticketMap.put(uniqueKey.toString(), issuer);

                if (logger.isDebugEnabled())
                {
                    logger.debug("+-+-+-+- The successful authentication is: " + "{\"entry\":{\"id\":\"" + uniqueKey
                            + "\",\"userId\":\"" + issuer + "\"}}");
                }

                // confirming here that all is OK
                // example
                // {"entry":{"id":"TICKET_592436e1f212f572cf9ff0e1c4283d0e74442d2e","userId":"admin@app.activiti.com"}}
                out.print("{\"entry\":{\"id\":\"" + uniqueKey + "\",\"userId\":\"" + issuer + "\"}}");
                out.flush();

                logger.info("Exit doFilter (" + ran + ")");

            } else
            {
                // we do not need to peek the body here
                // just need to to be able to add the "X-Alfresco-Remote-User" for Alfresco
                HeaderMapRequestWrapper requestWrapper = new HeaderMapRequestWrapper(req, false);

                // getting the positioned user from the jwt token
                // and position it in the header request

                // getting the header
                String headerSet = Optional.ofNullable(setHeaderFromAuthorizationHeader(requestWrapper))
                        .orElse(setHeaderFromAlfTicket(requestWrapper));

                if (headerSet != null && !headerSet.isEmpty())
                {
                    // found a valid authorisation
                    chain.doFilter(requestWrapper, response); // Goes to default servlet.
                    logger.info("Exit doFilter " + " (" + ran + ")");
                } else
                {
                    returnUnauthorized(response);
                    // unauthorized
                    logger.info(
                            "+-+-+-+-+-+-+ unauthorized returned because Authorization or ALF_TICKET not present or not valid");
                    logger.info("Exit doFilter (" + ran + ")");

                    return;
                }
            }
        } else
        {
            chain.doFilter(request, response); // Goes to default servlet.
            logger.info("Exit doFilter" + " (" + ran + ")");
        }
    }

    private String SetRemoteUser(String user, HeaderMapRequestWrapper requestWrapper)
    {
        requestWrapper.addHeader("X-Alfresco-Remote-User", user);
        return user;
    }

    /**
     * Set header from Authorisation.
     */
    private String setHeaderFromAlfTicket(HeaderMapRequestWrapper requestWrapper)
    {
        Optional<String> ticket = Optional.ofNullable(requestWrapper.getParameter("alf_ticket"));

        return ticket.isPresent() ? SetRemoteUser((String) ticketMap.get(ticket.get()), requestWrapper) : null;
    }

    /**
     * Set header from Authorisation. It consist of position the
     * "X-Alfresco-Remote-User" header for Alfresco pass through
     */
    private String setHeaderFromAuthorizationHeader(HeaderMapRequestWrapper requestWrapper)
    {

        String remoteUser = getHeaderFromAuthorizationHeader(requestWrapper);

        // position the header for Alfresco pass through
        if (remoteUser != null && !remoteUser.isEmpty())
            requestWrapper.addHeader("X-Alfresco-Remote-User", remoteUser);

        return remoteUser;
    }

    /**
     * get user from Authorisation.
     */
    private String getHeaderFromAuthorizationHeader(HeaderMapRequestWrapper requestWrapper)
    {
        // getting the positioned user from the jwt token
        String authorization = requestWrapper.getHeader("Authorization");

        if (authorization != null && !authorization.isEmpty())
        {
            // get second part of it, skip Basic<space>
            String parts[] = authorization.split(" ");
            if (parts != null && parts.length > 1)
            {
                // decode the base 64 because it is encoded twice in base 64
                byte[] decodedBytes = Base64.getDecoder().decode(parts[1]);
                String jwtStill = new String(decodedBytes);

                String partsToken[] = jwtStill.split(":");
                if (partsToken != null && partsToken.length > 1)
                {

                    // try to find the ticket in the map
                    String remoteUser = ticketMap.get(partsToken[1]);

                    if (logger.isDebugEnabled())
                    {
                        logger.debug("+-+-+-+- The Claimed user is: " + remoteUser);
                        logger.debug("+-+-+-+- The token is: " + partsToken[1]);
                    }

                    return remoteUser;
                }
            }
        }
        return null;
    }

    @SuppressWarnings("unused")
    public String createJWTEncodedB64(String id, String issuer, String subject, long ttlMillis, String secret)
    {
        // Encode data on your side using BASE64
        byte[] bytesEncoded = Base64.getEncoder().encode(createJWT(id, issuer, subject, ttlMillis, secret).getBytes());
        return new String(bytesEncoded).replaceAll("=+$", "");

    }

    // Sample method to validate and read the JWT encoded in base 64
    private Claims parseJWTEncodedB64(String jwtBase64, String secret)
    {

        byte[] decodedBytes = Base64.getDecoder().decode(jwtBase64);
        String jwt = new String(decodedBytes);

        return parseJWT(jwt, secret);
    }

    /**
     * Parse jwt token
     * 
     * @param jwt
     *            the token
     * @param secret
     * @return Claims
     */
    private Claims parseJWT(String jwt, String secret)
    {

        // This line will throw an exception if it is not a signed JWS (as expected)
        Claims claims = Jwts.parser().setSigningKey(DatatypeConverter.parseBase64Binary(secret)).parseClaimsJws(jwt)
                .getBody();

        if (logger.isDebugEnabled())
        {
            claims.forEach((k, v) ->
            {
                logger.debug("Claim: " + k + " : " + v);
            });
        }

        return claims;

    }

    /**
     * Method that is used to create the jwt token
     * 
     * @param Id
     *            that can be used to identify the token
     * @param issuer
     *            this will contain the user id. i.e. admin@app.activiti.com
     * @param subject
     *            Can be used for whatever
     * @param ttlMillis
     *            Time to live of this token
     * @param secret
     *            Key that is used to encrypt the token
     * @return
     */
    public String createJWT(String id, String issuer, String subject, long ttlMillis, String secret)
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

    @Override
    public void init(FilterConfig filterConfig) throws ServletException
    {
        this.filterConfig = filterConfig;
    }

    /**
     * Allow adding additional headers entries to a request and peek content if
     * peekBody is true.
     * 
     * See:
     * https://stackoverflow.com/questions/2811769/adding-an-http-header-to-the-request-in-a-servlet-filter
     * Seet:
     * http://sandeepmore.com/blog/2010/06/12/modifying-http-headers-using-java/
     * http://bijubnair.blogspot.de/2008/12/adding-header-information-to-existing.html
     * 
     */
    public class HeaderMapRequestWrapper extends HttpServletRequestWrapper
    {
        private byte[] body;

        private boolean peekBody = false;

        /**
         * This method should only be
         * 
         * @return bytes of the body.
         */
        public byte[] getStoredBody()
        {
            return body;
        }

        /**
         * 
         * @param request
         * @param peekBody
         */
        public HeaderMapRequestWrapper(HttpServletRequest request, boolean peekBody) {
            super(request);

            if (peekBody == true)
            {
                try
                {
                    // duplicate the body so it can be read more then once
                    final InputStream in = request.getInputStream();
                    Vector<Byte> bodyVector = new Vector<Byte>();
                    for (int b = 0; ((b = in.read()) >= 0);)
                    {
                        bodyVector.add((byte) b);
                    }
                    body = new byte[bodyVector.size()];
                    for (int i = 0; i < bodyVector.size(); i++)
                    {
                        body[i] = bodyVector.get(i);
                    }
                    in.close();
                } catch (IOException ex)
                {
                    body = new byte[0];
                    // add some log
                }
            }
        }

        /**
         * construct a wrapper for this request
         * 
         * @param request
         */
        public HeaderMapRequestWrapper(HttpServletRequest request) {
            super(request);
            peekBody = false;
        }

        private Map<String, String> headerMap = new HashMap<String, String>();

        /**
         * add a header with given name and value
         * 
         * @param name
         * @param value
         */
        public void addHeader(String name, String value)
        {
            headerMap.put(name, value);
        }

        @Override
        public String getHeader(String name)
        {
            String headerValue = super.getHeader(name);
            // requestWrapper YWRtaW5AYXBwLmFjdGl2aXRpLmNvbTphZG1pbg==
            if (headerMap.containsKey(name))
            {
                headerValue = headerMap.get(name);
            }
            return headerValue;
        }

        /**
         * get the Header names
         */
        @Override
        public Enumeration<String> getHeaderNames()
        {
            List<String> names = Collections.list(super.getHeaderNames());
            for (String name : headerMap.keySet())
            {
                names.add(name);
            }
            return Collections.enumeration(names);
        }

        @Override
        public Enumeration<String> getHeaders(String name)
        {
            List<String> values = Collections.list(super.getHeaders(name));
            if (headerMap.containsKey(name))
            {
                values.add(headerMap.get(name));
            }
            return Collections.enumeration(values);
        }

        @Override
        public ServletInputStream getInputStream() throws IOException
        {
            if (peekBody == true)
                return new DelegatingServletInputStream(new ByteArrayInputStream(body));
            else
                return super.getInputStream();

        }

    }

}
