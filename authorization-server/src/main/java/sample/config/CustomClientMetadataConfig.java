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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.oidc.OidcClientRegistration;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientConfigurationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.authentication.OidcClientRegistrationAuthenticationProvider;
import org.springframework.security.oauth2.server.authorization.oidc.converter.OidcClientRegistrationRegisteredClientConverter;
import org.springframework.security.oauth2.server.authorization.oidc.converter.RegisteredClientOidcClientRegistrationConverter;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

/**
 * @author Joe Grandja
 */
final class CustomClientMetadataConfig {
	private static final String CLIENT_SETTINGS_NAMESPACE = "settings.client.";

	private static final String RESOURCE_IDS_KEY = "resource_ids";

	static Consumer<List<AuthenticationProvider>> configureCustomClientMetadataConverters() {
		return (authenticationProviders) -> {
			CustomRegisteredClientConverter registeredClientConverter =
					new CustomRegisteredClientConverter();
			CustomClientRegistrationConverter clientRegistrationConverter =
					new CustomClientRegistrationConverter();

			authenticationProviders.forEach((authenticationProvider) -> {
				if (authenticationProvider instanceof OidcClientRegistrationAuthenticationProvider provider) {
					provider.setRegisteredClientConverter(registeredClientConverter);
					provider.setClientRegistrationConverter(clientRegistrationConverter);
				}
				if (authenticationProvider instanceof OidcClientConfigurationAuthenticationProvider provider) {
					provider.setClientRegistrationConverter(clientRegistrationConverter);
				}
			});
		};
	}

	static List<String> getResourceIds(ClientSettings clientSettings) {
		return clientSettings.getSetting(CLIENT_SETTINGS_NAMESPACE.concat(RESOURCE_IDS_KEY));
	}

	private static final class CustomRegisteredClientConverter
			implements Converter<OidcClientRegistration, RegisteredClient> {

		private final OidcClientRegistrationRegisteredClientConverter delegate =
				new OidcClientRegistrationRegisteredClientConverter();

		@Override
		public RegisteredClient convert(OidcClientRegistration clientRegistration) {
			RegisteredClient registeredClient = this.delegate.convert(clientRegistration);
			ClientSettings.Builder clientSettingsBuilder = ClientSettings.withSettings(
					registeredClient.getClientSettings().getSettings());
			if (clientRegistration.getClaims().get(RESOURCE_IDS_KEY) != null) {
				clientSettingsBuilder.setting(CLIENT_SETTINGS_NAMESPACE.concat(RESOURCE_IDS_KEY),
						clientRegistration.getClaims().get(RESOURCE_IDS_KEY));
			}
			return RegisteredClient.from(registeredClient)
					.clientSettings(clientSettingsBuilder.build())
					.build();
		}

	}

	private static final class CustomClientRegistrationConverter
			implements Converter<RegisteredClient, OidcClientRegistration> {

		private final RegisteredClientOidcClientRegistrationConverter delegate =
				new RegisteredClientOidcClientRegistrationConverter();

		@Override
		public OidcClientRegistration convert(RegisteredClient registeredClient) {
			OidcClientRegistration clientRegistration = this.delegate.convert(registeredClient);
			Map<String, Object> claims = new HashMap<>(clientRegistration.getClaims());
			ClientSettings clientSettings = registeredClient.getClientSettings();
			if (getResourceIds(clientSettings) != null) {
				claims.put(RESOURCE_IDS_KEY, getResourceIds(clientSettings));
			}
			return OidcClientRegistration.withClaims(claims).build();
		}

	}

}
