package org.sinaure.instantsecurity.services;

public class ResourceAlreadyExistException extends Exception {
	public ResourceAlreadyExistException(String errorMessage) {
        super(errorMessage );
    }
}
