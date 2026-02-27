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

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.converter.OAuth2ClientRegistrationRegisteredClientConverter;
import org.springframework.security.oauth2.server.authorization.http.converter.OAuth2ClientRegistrationHttpMessageConverter;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.client.RestClient;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.InetAddress;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author Joe Grandja
 * @see <a href="https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00">OAuth Client ID Metadata Document</a>
 */
public final class ClientIdMetadataDocumentRegisteredClientRepository implements RegisteredClientRepository {

	private final Cache cache = new Cache();

	private Converter<OAuth2ClientRegistration, RegisteredClient> registeredClientConverter = new OAuth2ClientRegistrationRegisteredClientConverter();

	private ClientIdMetadataDocumentResolver metadataDocumentResolver = new DefaultClientIdMetadataDocumentResolver();

	private ClientMetadataValidator metadataValidator = new DefaultClientMetadataValidator();

	@Override
	public void save(RegisteredClient registeredClient) {
		// No-op
	}

	@Override
	public RegisteredClient findById(String id) {
		Assert.hasText(id, "id cannot be empty");
		return this.cache.getById(id);
	}

	@Override
	public RegisteredClient findByClientId(String clientId) {
		Assert.hasText(clientId, "clientId cannot be empty");
		RegisteredClient cachedRegisteredClient = this.cache.getByClientId(clientId);
		if (cachedRegisteredClient != null) {
			return cachedRegisteredClient;
		}
		ClientIdMetadataDocumentResolver.Result result = this.metadataDocumentResolver.resolve(clientId);
		if (result == null) {
			return null;
		}
		OAuth2ClientRegistration clientRegistration = result.clientRegistration();
		if (!this.metadataValidator.validate(clientId, clientRegistration)) {
			return null;
		}
		RegisteredClient registeredClient = this.registeredClientConverter.convert(clientRegistration);
		registeredClient = RegisteredClient.from(registeredClient)
			.id(clientId)
			.clientId(clientId)
			.build();
		if (result.responseAttributes().cacheMaxAgeSeconds() >= 0) {
			long cacheMaxAgeSeconds = result.responseAttributes().cacheMaxAgeSeconds();
			this.cache.put(registeredClient, System.currentTimeMillis() + cacheMaxAgeSeconds * 1000);
		}
		return registeredClient;
	}

	public void setRegisteredClientConverter(Converter<OAuth2ClientRegistration, RegisteredClient> registeredClientConverter) {
		Assert.notNull(registeredClientConverter, "registeredClientConverter cannot be null");
		this.registeredClientConverter = registeredClientConverter;
	}

	public void setMetadataDocumentResolver(ClientIdMetadataDocumentResolver metadataDocumentResolver) {
		Assert.notNull(metadataDocumentResolver, "metadataDocumentResolver cannot be null");
		this.metadataDocumentResolver = metadataDocumentResolver;
	}

	public void setMetadataValidator(ClientMetadataValidator metadataValidator) {
		Assert.notNull(metadataValidator, "metadataValidator cannot be null");
		this.metadataValidator = metadataValidator;
	}

	public interface ClientIdMetadataDocumentResolver {

		Result resolve(String clientIdUrl);

		record Result(OAuth2ClientRegistration clientRegistration, ResponseAttributes responseAttributes) {
		}

		record ResponseAttributes(long cacheMaxAgeSeconds) {
		}

	}

	public interface ClientMetadataValidator {

		boolean validate(String clientIdUrl, OAuth2ClientRegistration clientRegistration);

	}

	public static final class DefaultClientIdMetadataDocumentResolver implements ClientIdMetadataDocumentResolver {

		private boolean allowHttpUrlForClientIdentifier;

		private boolean allowLoopbackHostForClientIdentifier;

		// @formatter:off
		private final RestClient restClient = RestClient.builder()
				.configureMessageConverters((messageConverters) ->
					messageConverters.addCustomConverter(new OAuth2ClientRegistrationHttpMessageConverter())
				)
				.build();
		// @formatter:on

		@Override
		public Result resolve(String clientIdUrl) {
			if (!isClientIdentifierValid(clientIdUrl)) {
				return null;
			}
			return retrieve(clientIdUrl);
		}

		public void setAllowHttpUrlForClientIdentifier(boolean allowHttpUrlForClientIdentifier) {
			this.allowHttpUrlForClientIdentifier = allowHttpUrlForClientIdentifier;
		}

		public void setAllowLoopbackHostForClientIdentifier(boolean allowLoopbackHostForClientIdentifier) {
			this.allowLoopbackHostForClientIdentifier = allowLoopbackHostForClientIdentifier;
		}

		private boolean isClientIdentifierValid(String clientIdUrl) {
			try {
				UriComponents uri = UriComponentsBuilder.fromUriString(clientIdUrl).build();
				if ("http".equalsIgnoreCase(uri.getScheme()) && !this.allowHttpUrlForClientIdentifier) {
					return false;
				}
				if (uri.getHost() == null) {
					return false;
				}
				if (isLoopbackHost(uri.getHost()) && !this.allowLoopbackHostForClientIdentifier) {
					return false;
				}
				if (isPrivateHost(uri.getHost())) {
					return false;
				}
				if (uri.getUserInfo() != null) {
					return false;
				}
				if (uri.getFragment() != null) {
					return false;
				}
				String path = uri.getPath();
				if (path == null || path.isEmpty()) {
					return false;
				}
				for (String pathSegment : uri.getPathSegments()) {
					if (".".equals(pathSegment) || "..".equals(pathSegment)) {
						return false;
					}
				}
				return true;
			}
			catch (Exception ex) {
				return false;
			}
		}

		private static boolean isLoopbackHost(String host) {
			if ("localhost".equalsIgnoreCase(host.trim())) {
				return true;
			}
			try {
				InetAddress address = InetAddress.getByName(host.trim());
				return address.isLoopbackAddress();
			}
			catch (Exception ex) {
				return false;
			}
		}

		private static boolean isPrivateHost(String host) {
			try {
				InetAddress address = InetAddress.getByName(host.trim());
				return address.isSiteLocalAddress();
			}
			catch (Exception ex) {
				return false;
			}
		}

		private Result retrieve(String clientIdUrl) {
			try {
				ResponseEntity<OAuth2ClientRegistration> response = this.restClient.get()
					.uri(clientIdUrl)
					.retrieve()
					.toEntity(OAuth2ClientRegistration.class);
				OAuth2ClientRegistration clientRegistration = response.getBody();
				long cacheMaxAgeSeconds = Cache.getMaxAgeSeconds(response.getHeaders());
				ResponseAttributes responseAttributes = new ResponseAttributes(cacheMaxAgeSeconds);
				return new Result(clientRegistration, responseAttributes);
			}
			catch (Exception ex) {
				return null;
			}
		}

	}

	public static final class DefaultClientMetadataValidator implements ClientMetadataValidator {

		private static final Set<String> ALLOWED_TOKEN_ENDPOINT_AUTH_METHODS = Set.of(
				ClientAuthenticationMethod.NONE.getValue(),
				ClientAuthenticationMethod.PRIVATE_KEY_JWT.getValue(),
				ClientAuthenticationMethod.TLS_CLIENT_AUTH.getValue(),
				ClientAuthenticationMethod.SELF_SIGNED_TLS_CLIENT_AUTH.getValue());

		@Override
		public boolean validate(String clientIdUrl, OAuth2ClientRegistration clientRegistration) {
			String clientId = clientRegistration.getClientId();
			if (!StringUtils.hasText(clientId)) {
				return false;
			}
			if (!clientIdUrl.equals(clientId)) {
				return false;
			}
			if (StringUtils.hasText(clientRegistration.getClientSecret())) {
				return false;
			}
			if (clientRegistration.getClientSecretExpiresAt() != null) {
				return false;
			}
			if (CollectionUtils.isEmpty(clientRegistration.getRedirectUris())) {
				return false;
			}
			if (!StringUtils.hasText(clientRegistration.getClientName())) {
				return false;
			}
			String tokenEndpointAuthenticationMethod = clientRegistration.getTokenEndpointAuthenticationMethod();
			if (StringUtils.hasText(tokenEndpointAuthenticationMethod) &&
					!ALLOWED_TOKEN_ENDPOINT_AUTH_METHODS.contains(tokenEndpointAuthenticationMethod)) {
				return false;
			}
			return true;
		}

	}

	private static final class Cache {

		private static final long DEFAULT_CACHE_MAX_AGE_SECONDS = 300;	// 5 minutes

		private static final long CACHE_MAX_AGE_SECONDS = 86400;	// 24 hours

		private static final Pattern MAX_AGE_PATTERN = Pattern.compile("\\bmax-age=(\\d+)\\b", Pattern.CASE_INSENSITIVE);

		private final Map<String, CacheEntry> clientIdToEntry = new ConcurrentHashMap<>();

		private final Map<String, CacheEntry> idToEntry = new ConcurrentHashMap<>();

		private RegisteredClient getById(String id) {
			Assert.hasText(id, "id cannot be empty");
			CacheEntry cacheEntry = this.idToEntry.get(id);
			if (cacheEntry == null) {
				return null;
			}
			if (cacheEntry.isExpired()) {
				evict(cacheEntry.registeredClient);
				return null;
			}
			return cacheEntry.registeredClient;
		}

		private RegisteredClient getByClientId(String clientId) {
			Assert.hasText(clientId, "clientId cannot be empty");
			CacheEntry cacheEntry = this.clientIdToEntry.get(clientId);
			if (cacheEntry == null) {
				return null;
			}
			if (cacheEntry.isExpired()) {
				evict(cacheEntry.registeredClient);
				return null;
			}
			return cacheEntry.registeredClient;
		}

		private void put(RegisteredClient registeredClient, long expiryMillis) {
			CacheEntry cacheEntry = new CacheEntry(registeredClient, expiryMillis);
			this.clientIdToEntry.put(registeredClient.getClientId(), cacheEntry);
			this.idToEntry.put(registeredClient.getId(), cacheEntry);
		}

		private void evict(RegisteredClient registeredClient) {
			this.clientIdToEntry.remove(registeredClient.getClientId());
			this.idToEntry.remove(registeredClient.getId());
		}

		private static long getMaxAgeSeconds(HttpHeaders headers) {
			String cacheControl = headers.getFirst(HttpHeaders.CACHE_CONTROL);
			if (cacheControl != null) {
				if (cacheControl.toLowerCase().contains("no-store")) {
					return -1;
				}
				Matcher matcher = MAX_AGE_PATTERN.matcher(cacheControl);
				if (matcher.find()) {
					long maxAge = Long.parseLong(matcher.group(1));
					if (maxAge <= 0) {
						return -1;
					}
					return Math.min(maxAge, CACHE_MAX_AGE_SECONDS);
				}
			}
			return DEFAULT_CACHE_MAX_AGE_SECONDS;
		}

		private record CacheEntry(RegisteredClient registeredClient, long expiryMillis) {

			boolean isExpired() {
				return System.currentTimeMillis() > this.expiryMillis;
			}

		}

	}

}
