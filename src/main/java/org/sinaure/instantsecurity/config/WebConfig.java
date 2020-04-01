package org.sinaure.instantsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.BufferingClientHttpRequestFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.client.RestTemplate;

import java.util.List;

@Configuration
public class WebConfig {
	
	
    @Bean
    public RestTemplate restTemplate() {

    	RestTemplate restTemplate = new RestTemplate();
    	// Get the default messageConverterList
    	List<HttpMessageConverter<?>> messageConverterList = restTemplate.getMessageConverters();

    	// Add MappingJackson2HttpMessageConverter and MarshallingHttpMessageConverter
    	// to the messageConverterList
    	MappingJackson2HttpMessageConverter jsonMessageConverter = new MappingJackson2HttpMessageConverter();
    	messageConverterList.add(jsonMessageConverter);
    	restTemplate.setMessageConverters(messageConverterList);
		SimpleClientHttpRequestFactory httpFactory = new SimpleClientHttpRequestFactory();
		httpFactory.setOutputStreaming(false);
		restTemplate.setRequestFactory(new BufferingClientHttpRequestFactory(httpFactory));
    	return restTemplate;
    }
    
}