package org.springboot.greetingapp.Controller;

import org.springboot.greetingapp.Model.Message;
import org.springboot.greetingapp.Services.GreetingServices;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/greeting")
public class GreetingController {
    GreetingServices greetingServices;
    public GreetingController(GreetingServices greetingServices) {
        this.greetingServices = greetingServices;
    }
    Message message;
    @GetMapping("/get")
    public String greeting() {
        return "Hello World";
    }
    @PostMapping("/post")
    public String greetingPost(@RequestBody Message message) {
        return "Hello Post Request from"+message.getMessage();
    }
    @PutMapping("/put/{message}")
    public String greetingPut(@PathVariable String message) {
        return "Hello Put Request from"+message;
    }
    @DeleteMapping("/delete/{message}")
    public String greetingDelete(@PathVariable String message) {
        return "Hello Delete Request from"+message;
    }
    @PatchMapping("/patch/{message}")
    public String greetingPatch(@PathVariable String message) {
        return "Hello Patch Request from"+message;
    }

    @GetMapping("/services")
    public String greetingServices() {
        return greetingServices.getGreeting();
    }
}
