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
package sample;

import java.time.LocalDateTime;

import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.web.client.RestClient;

/**
 * @author Joe Grandja
 */
public class WeatherService {

	private final RestClient restClient = RestClient.create();

	@Tool(description = "Get the temperature (in celsius) for a specific location")
	public WeatherResponse getTemperature(@ToolParam(description = "The location latitude") double latitude,
			@ToolParam(description = "The location longitude") double longitude) {

		WeatherResponse weatherResponse = this.restClient
				.get()
				.uri("https://api.open-meteo.com/v1/forecast?latitude={latitude}&longitude={longitude}&current=temperature_2m",
						latitude, longitude)
				.retrieve()
				.body(WeatherResponse.class);
		
		return weatherResponse;

	}

	public record WeatherResponse(Current current) {
		public record Current(LocalDateTime time, int interval, double temperature_2m) {
		}
	}

}