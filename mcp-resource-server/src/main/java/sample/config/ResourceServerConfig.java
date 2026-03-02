/*
 * Copyright 2020-2026 the original author or authors.
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

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtAudienceValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.OAuth2ProtectedResourceMetadata;
import org.springframework.security.web.SecurityFilterChain;

import java.util.function.Consumer;

/**
 * @author Joe Grandja
 */
@EnableWebSecurity
@EnableMethodSecurity
@Configuration(proxyBeanMethods = false)
public class ResourceServerConfig {
	private static final String RESOURCE_IDENTIFIER = "http://127.0.0.1:8090";

	// @formatter:off
	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests(authorize ->
				authorize
					.requestMatchers("/mcp").permitAll()
					.requestMatchers("/messages/**").hasAuthority("SCOPE_message.read")
			)
			.csrf(csrf ->
				csrf
					.ignoringRequestMatchers("/mcp"))
			.oauth2ResourceServer(resourceServer ->
				resourceServer
					.jwt(Customizer.withDefaults())
					.protectedResourceMetadata(protectedResourceMetadata ->
						protectedResourceMetadata
							.protectedResourceMetadataCustomizer(protectedResourceMetadataCustomizer()))
			);
		return http.build();
	}
	// @formatter:on

	// @formatter:off
	private static Consumer<OAuth2ProtectedResourceMetadata.Builder> protectedResourceMetadataCustomizer() {
		return (builder) ->
				builder
					.authorizationServer("http://127.0.0.1:9000")
					.scope("message.read")
					.resourceName("Spring MCP Resource Server");
	}
	// @formatter:on

	@Bean
	public JwtDecoder jwtDecoder(@Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}") String jwkSetUri) {
		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
		OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators.createDefaultWithValidators(
				// Validate 'aud' claim with expected resource identifier
				new JwtAudienceValidator(RESOURCE_IDENTIFIER));
		jwtDecoder.setJwtValidator(jwtValidator);

		return jwtDecoder;
	}

}