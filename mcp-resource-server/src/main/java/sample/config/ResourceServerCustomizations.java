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

import sample.server.resource.metadata.OAuth2ProtectedResourceMetadataEndpointFilter;
import sample.server.resource.metadata.ResourceIdentifier;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtAudienceValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

/**
 * @author Joe Grandja
 */
@Configuration(proxyBeanMethods = false)
public class ResourceServerCustomizations {

	@Bean
	public ResourceIdentifier resourceIdentifier() {
		return new ResourceIdentifier("http://127.0.0.1:8090");
	}

	@Bean
	public OAuth2ProtectedResourceMetadataEndpointFilter metadataEndpointFilter(ResourceIdentifier resourceIdentifier) {
		OAuth2ProtectedResourceMetadataEndpointFilter protectedResourceMetadataEndpointFilter =
				new OAuth2ProtectedResourceMetadataEndpointFilter(resourceIdentifier);
		protectedResourceMetadataEndpointFilter.setProtectedResourceMetadataCustomizer((protectedResourceMetadata) ->
			protectedResourceMetadata
					.authorizationServer("http://localhost:9000")
					.scope("message.read")
					.bearerMethod("header")
					.resourceName("MCP Resource Server")
		);
		return protectedResourceMetadataEndpointFilter;
	}

	@Bean
	public JwtDecoder jwtDecoder(ResourceIdentifier resourceIdentifier,
									@Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}") String jwkSetUri) {

		NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
		OAuth2TokenValidator<Jwt> jwtValidator = JwtValidators.createDefaultWithValidators(
				new JwtAudienceValidator(resourceIdentifier.getId()));
		jwtDecoder.setJwtValidator(jwtValidator);

		return jwtDecoder;
	}

}