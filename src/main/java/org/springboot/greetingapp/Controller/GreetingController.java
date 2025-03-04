package org.springboot.greetingapp.Controller;

import jakarta.websocket.server.PathParam;
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

    @GetMapping("/query")
    public String query(@PathParam("firstName") String firstName, @PathParam("lastName") String lastName){
        if(firstName != null && lastName != null)
            return "Hello "+firstName+" "+lastName+"Welcome to My Application";
        else if(firstName != null)
            return "Hello "+firstName+" Welcome to Application";
        else if(lastName != null)
            return "Hello "+lastName+" Welcome to Application";
        else
            return "Hello, Welcome to Application";
    }

    @PostMapping("/save")
    public String save(@RequestBody Message message){
        return greetingServices.save(message).getMessage();
    }
    @GetMapping("/find/{ID}")
    public Message findbyID(@PathVariable Long ID){
        return greetingServices.findbyID(ID);
    }

    }

