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
package sample.web;

import org.springframework.ai.chat.client.ChatClient;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * @author Joe Grandja
 */
@Controller
public class WeatherController {
    private final ChatClient chatClient;

    public WeatherController(ChatClient chatClient) {
        this.chatClient = chatClient;
    }

    @GetMapping("/weather")
    public String weather(
            @RequestParam(value="city", required = false) String city,
            Model model) {

        if (StringUtils.hasText(city)) {
            String currentWeather = this.chatClient.prompt(
                    "What is the weather in %s right now?".formatted(city))
                    .call()
                    .content();

            model.addAttribute("city", city);
            model.addAttribute("currentWeather", currentWeather);
        }

        return "weather";
    }

}
