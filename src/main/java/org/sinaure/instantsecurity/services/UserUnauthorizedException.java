package org.sinaure.instantsecurity.services;

public class UserUnauthorizedException extends Exception {
	public UserUnauthorizedException(String errorMessage) {
        super(errorMessage );
    }
}
