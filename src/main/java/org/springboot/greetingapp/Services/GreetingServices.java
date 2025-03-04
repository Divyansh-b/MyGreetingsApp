package org.springboot.greetingapp.Services;

import org.springframework.stereotype.Service;

@Service
public class GreetingServices {
    String greeting;
    public GreetingServices() {
        greeting = "Hello User";
    }
    public String getGreeting() {
        return greeting;
    }
    public void setGreeting(String greeting) {
        this.greeting = greeting;
    }
}
