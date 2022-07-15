package com.skku_tinder.demo.exception;

public class UserAuthException extends RuntimeException{

    public UserAuthException() {
        super();
    }

    public UserAuthException(String message) {
        super(message);
    }
}
