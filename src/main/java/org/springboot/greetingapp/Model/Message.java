package org.springboot.greetingapp.Model;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


@AllArgsConstructor
@NoArgsConstructor
@Getter
@Setter
public class Message {
    String message;
    Long MessageID;


    public Message(String message) {
    }
}
