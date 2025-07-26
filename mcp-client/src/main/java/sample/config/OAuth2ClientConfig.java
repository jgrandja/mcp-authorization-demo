/*
 * Copyright 2020-2025 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.config;

import java.util.Map;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientProperties;
import org.springframework.boot.security.oauth2.client.autoconfigure.OAuth2ClientPropertiesMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

/**
 * @author Joe Grandja
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties({OAuth2ClientProperties.class})
public class OAuth2ClientConfig {

    @Bean
    public ManagedClientRegistrationRepository clientRegistrationRepository(OAuth2ClientProperties clientProperties) {
        ManagedClientRegistrationRepository clientRegistrationRepository = new ManagedClientRegistrationRepository();
        Map<String, ClientRegistration> clientRegistrations = new OAuth2ClientPropertiesMapper(clientProperties).asClientRegistrations();
        clientRegistrations.values().forEach(clientRegistrationRepository::register);
        return clientRegistrationRepository;
    }

}