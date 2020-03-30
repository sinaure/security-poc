package org.sinaure.instantsecurity.services;

public class TokenSet {
	private String authToken;
	private String refreshToken;
	public TokenSet( String authToken, String refreshToken) {
		this.authToken =authToken;
		this.refreshToken = refreshToken;
	};
	public TokenSet() {
	};

	public String getRefreshToken() {
		return refreshToken;
	}
	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}
	public String getAuthToken() {
		return authToken;
	}
	public void setAuthToken(String authToken) {
		this.authToken = authToken;
	}
}
