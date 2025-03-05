package org.springboot.greetingapp.Controller;

import jakarta.websocket.server.PathParam;
import org.springboot.greetingapp.Interfaces.IGreetingInterface;
import org.springboot.greetingapp.Model.Message;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/greeting")  // Base URL for all endpoints: /greeting
public class GreetingController {
    @Autowired
    IGreetingInterface greetingInterface;





    Message message;

    /**
     * UC1-GreetingRestAPI
     * GET request - Returns a simple greeting message.
     * URL: http://localhost:8080/greeting/get
     */
    @GetMapping("/get")
    public String greeting() {
        return "Hello World";
    }

    /**
     * POST request - Accepts a message in the request body and returns a greeting.
     * URL: http://localhost:8080/greeting/post
     * Body: { "message": "John" }
     */
    @PostMapping("/post")
    public String greetingPost(@RequestBody Message message) {
        return "Hello Post Request from " + message.getMessage();
    }

    /**
     * PUT request - Updates a message via URL path variable.
     * URL: http://localhost:8080/greeting/put/{message}
     */
    @PutMapping("/put/{message}")
    public String greetingPut(@PathVariable String message) {
        return "Hello Put Request from " + message;
    }

    /**
     * DELETE request - Deletes a message via URL path variable.
     * URL: http://localhost:8080/greeting/delete/{message}
     */
    @DeleteMapping("/delete/{message}")
    public String greetingDelete(@PathVariable String message) {
        return "Hello Delete Request from " + message;
    }

    /**

     * PATCH request - Partially updates a message.
     * URL: http://localhost:8080/greeting/patch/{message}
     */
    @PatchMapping("/patch/{message}")
    public String greetingPatch(@PathVariable String message) {
        return "Hello Patch Request from " + message;
    }

    /**
     *   UC2-greetingInterface
     * GET request - Calls a service method and returns its response.
     * URL: http://localhost:8080/greeting/services
     */
    @GetMapping("/services")
    public String greetingInterface() {
        return greetingInterface.getGreeting();
    }

    /**
     *   UC3-QueryParams
     * GET request - Accepts query parameters for firstName and lastName.
     * URL Examples:
     * - http://localhost:8080/greeting/query?firstName=Abhay&lastName=Goyal
     * - http://localhost:8080/greeting/query?firstName=Abhay
     * - http://localhost:8080/greeting/query?lastName=Goyal
     */
    @GetMapping("/query")
    public String query(@PathParam("firstName") String firstName, @PathParam("lastName") String lastName) {
        if (firstName != null && lastName != null)
            return "Hello " + firstName + " " + lastName + ", Welcome to My Application";
        else if (firstName != null)
            return "Hello " + firstName + ", Welcome to Application";
        else if (lastName != null)
            return "Hello " + lastName + ", Welcome to Application";
        else
            return "Hello, Welcome to Application";
    }

    /**
     * UC5 - Saving Mwssage in DataBase
     * POST request - Saves a message using the service layer.
     * URL: http://localhost:8080/greeting/save
     * Body: { "message": "Hello Spring Boot" }
     */
    @PostMapping("/save")
    public String save(@RequestBody Message message) {
        return greetingInterface.save(message).getMessage();
    }

    /**
     * UC6- Find Message by ID
     * GET request - Finds a message by its ID.
     * URL: http://localhost:8080/greeting/find/{ID}
     */
    @GetMapping("/find/{ID}")
    public Message findbyID(@PathVariable Long ID) {
        return greetingInterface.findById(ID);
    }

    /**
     *   UC7-EditMessage
     * GET request - Retrieves all stored messages.
     * URL: http://localhost:8080/greeting/all
     */
    @GetMapping("/all")
    public List<Message> getAll() {
        return greetingInterface.listAllMessages();
    }

    /**
     *   UC7-EditMessage
     * PUT request - Updates a message by ID.
     * URL: http://localhost:8080/greeting/update/{ID}
     * Body: { "message": "Updated message" }
     */
    @PutMapping("/update/{ID}")
    public Message updateByID(@RequestBody Message message, @PathVariable Long ID) {
        return greetingInterface.updateById(message, ID);
    }

    /**
     *   UC8-DeleteMessages
     * DELETE request - Deletes a message by ID.
     * URL: http://localhost:8080/greeting/delete/{ID}
     */

    @DeleteMapping("/delete/{ID}")
    public String deleteByID(@PathVariable Long ID) {
        return greetingInterface.deleteMessage(ID);
    }


}
