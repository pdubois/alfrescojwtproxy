package com.adf.security.adfsecurity5;

import org.mitre.dsmiley.httpproxy.ProxyServlet;
import org.springframework.boot.bind.RelaxedPropertyResolver;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.ServletRegistrationBean;
import org.springframework.context.EnvironmentAware;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

@Configuration
public class AlfrescoProxyServletConfiguration implements EnvironmentAware {

    @Bean
    public ServletRegistrationBean servletRegistrationBean(){
      System.out.println("***********************target_url is:" + propertyResolver.getProperty("target_url"));
      System.out.println("***********************servlet_url is:" + propertyResolver.getProperty("servlet_url"));
      ServletRegistrationBean servletRegistrationBean = new ServletRegistrationBean(new ProxyServlet(), propertyResolver.getProperty("servlet_url"));
      servletRegistrationBean.addInitParameter("targetUri", propertyResolver.getProperty("target_url"));
      servletRegistrationBean.addInitParameter(ProxyServlet.P_LOG, propertyResolver.getProperty("logging_enabled", "true"));
      return servletRegistrationBean;
    }

    private RelaxedPropertyResolver propertyResolver;

    @Override
    public void setEnvironment(Environment environment) {
      this.propertyResolver = new RelaxedPropertyResolver(environment, "proxy.alfresco.");
    }
    
    @Bean
    public FilterRegistrationBean loggingFilter(){
        FilterRegistrationBean registrationBean 
          = new FilterRegistrationBean();
             
        registrationBean.setFilter(new AdfsecurityFilter());
        registrationBean.addUrlPatterns("/alfresco/*");
        registrationBean.addInitParameter("secret", propertyResolver.getProperty("secret"));
             
        return registrationBean;    
    }
  
  }