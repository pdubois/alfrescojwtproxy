package com.adf.security.adfsecurity5;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintWriter;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

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

import org.springframework.mock.web.DelegatingServletInputStream;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;



public class AdfsecurityFilter implements Filter
{

    @Override
    public void destroy()
    {

    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException
    {
        if (request instanceof HttpServletRequest)
        {
            HttpServletRequest req = (HttpServletRequest) request;
            
            String pathInfo = req.getPathInfo();
            // this under is done for 2 reasons:
            // HEADERS can not be added directly on the request
            // and BODY can only be read once
            HeaderMapRequestWrapper requestWrapper = new HeaderMapRequestWrapper(req);

            // check if trying to get a ticket by checking the following url:
            //  /alfresco/api/-default-/public/authentication/versions/1/tickets
            if(pathInfo.startsWith("/alfresco/api/-default-/public/authentication/versions/1/tickets") && 
                    req.getMethod().equalsIgnoreCase("POST"))
            {

                // requestWrapper.addHeader("remote_addr", remote_addr);
                System.out.println("****************  In AdfsecurityFilter: " + req.getPathInfo());
                System.out.println("****************  In AdfsecurityFilter password: " + req.getParameter("password"));

                
                String bodyString = new String(requestWrapper.getStoredBody());
                System.out.println("****************  In AdfsecurityFilter BODY: " + bodyString);
                
                ObjectMapper mapper = new ObjectMapper();
                JsonNode theJsonBody = mapper.readTree(bodyString);
                System.out.println("********The Claimed user is: " + theJsonBody.get("userId").toString());
                System.out.println("********The JWT token is: " + theJsonBody.get("password"));
                
                //Do here the JWT checking/verification
                //if All OK then
                requestWrapper.addHeader("X-Alfresco-Remote-User", theJsonBody.get("userId").toString());
               
                HttpServletResponse responseOK = (HttpServletResponse) response;
                
                //responseOK.setStatus(200);
                
                //responseOK.sendError(200);
                //responseOK.setCode(200);
                
                
                PrintWriter out = response.getWriter();
                response.setContentType("application/json");
                response.setCharacterEncoding("UTF-8");
                // Assuming your json object is **jsonObject**, perform the following, it will return your json object  
                out.print("{\"entry\":{\"id\":\"TICKET_tagada\",\"userId\":\"admin@app.activiti.com\"}}");
                out.flush();
                
                // When getting ticket body is a json similar to:
                // 
                // parse the JSON in bodyString and position the header with user it claims to be.
                
                // http://localhost:8082/alfresco/api/-default-/public/authentication/versions/1/tickets
                //chain.doFilter(requestWrapper, response); // Goal to default servlet.
            }
            else
            {
                //if All OK then
                requestWrapper.addHeader("X-Alfresco-Remote-User", "admin@app.activiti.com");
               
                chain.doFilter(requestWrapper, response); // Goes to default servlet.
            }
        } else
        {
            chain.doFilter(request, response); // Goes to default servlet.
        }
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException
    {

    }

    // https://stackoverflow.com/questions/2811769/adding-an-http-header-to-the-request-in-a-servlet-filter
    // http://sandeepmore.com/blog/2010/06/12/modifying-http-headers-using-java/
    // http://bijubnair.blogspot.de/2008/12/adding-header-information-to-existing.html
    /**
     * allow adding additional header entries to a request
     * 
     * @author wf
     * 
     */
    public class HeaderMapRequestWrapper extends HttpServletRequestWrapper
    {
        private byte[] body;
        
        /**
         * 
         * @return bytes of the body.
         */
        public byte[] getStoredBody()
        {
            return body;
        }
        
        /**
         * construct a wrapper for this request
         * 
         * @param request
         */
        public HeaderMapRequestWrapper(HttpServletRequest request) {
            super(request);
            try {
                //duplicate the body so it can be read more then once
                final InputStream in = request.getInputStream();
                Vector<Byte> bodyVector = new Vector<Byte>();
                for (int b = 0; ((b = in.read()) >= 0);) {
                    bodyVector.add((byte)b);
                }
                body = new byte[bodyVector.size()];
                for(int i = 0; i< bodyVector.size(); i++)
                {
                    body[i] = bodyVector.get(i);
                } 
                in.close();
            } catch (IOException ex) {
                body = new byte[0];
            }
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
            //if(name.startsWith("Authorization"))
            //    return null;
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
              //  if(!name.startsWith("Authorization"))
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
        public ServletInputStream getInputStream() throws IOException {

            return new DelegatingServletInputStream(new ByteArrayInputStream(body));

        }

    }

}
