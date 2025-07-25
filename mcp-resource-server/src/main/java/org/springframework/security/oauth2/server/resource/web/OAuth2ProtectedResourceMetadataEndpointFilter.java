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
package org.springframework.security.oauth2.server.resource.web;

import java.io.IOException;
import java.util.Map;
import java.util.function.Consumer;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A {@code Filter} that processes OAuth 2.0 Protected Resource Metadata Requests.
 *
 * @author Joe Grandja
 * @see OAuth2ProtectedResourceMetadata
 * @see <a target="_blank" href="https://www.rfc-editor.org/rfc/rfc9728.html#section-3.1">3.1. Protected Resource Metadata Request</a>
 */
public final class OAuth2ProtectedResourceMetadataEndpointFilter extends OncePerRequestFilter {

	private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<>() {
	};

	private static final GenericHttpMessageConverter<Object> JSON_MESSAGE_CONVERTER = HttpMessageConverters
			.getJsonMessageConverter();

	private final RequestMatcher requestMatcher = PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, "/.well-known/oauth-protected-resource");

	private Consumer<OAuth2ProtectedResourceMetadata.Builder> protectedResourceMetadataCustomizer = (protectedResourceMetadata) -> { };

    public void setProtectedResourceMetadataCustomizer(
			Consumer<OAuth2ProtectedResourceMetadata.Builder> protectedResourceMetadataCustomizer) {
		Assert.notNull(protectedResourceMetadataCustomizer, "protectedResourceMetadataCustomizer cannot be null");
		this.protectedResourceMetadataCustomizer = protectedResourceMetadataCustomizer;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.requestMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		OAuth2ProtectedResourceMetadata.Builder builder = OAuth2ProtectedResourceMetadata.builder();

		this.protectedResourceMetadataCustomizer.accept(builder);

		OAuth2ProtectedResourceMetadata protectedResourceMetadata = builder.build();

		ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
		httpResponse.setStatusCode(HttpStatus.OK);

		JSON_MESSAGE_CONVERTER.write(protectedResourceMetadata.getClaims(), STRING_OBJECT_MAP.getType(),
				MediaType.APPLICATION_JSON, httpResponse);
	}

}