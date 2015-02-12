package com.warrenstrange.googleauth;

import org.junit.Test;

import java.util.ArrayList;

import static org.junit.Assert.assertEquals;

public class GoogleAuthenticatorQRGeneratorTest {

	private static GoogleAuthenticatorKey credentials = new GoogleAuthenticatorKey("secretKey", 123456, new ArrayList<Integer>());
	
	@Test
	public void testGetOtpAuthURL() throws Exception {
		assertEquals("https://chart.googleapis.com/chart?chs=200x200&chld=M%7C0&cht=qr&chl=otpauth%3A%2F%2Ftotp%2FAcme%3Aalice%40example.com%3Fsecret%3DsecretKey%26issuer%3DAcme",
				GoogleAuthenticatorQRGenerator.getOtpAuthURL("Acme", "alice@example.com", credentials));
	}

	@Test
	public void testGetOtpAuthTotpURL() throws Exception {
		assertEquals("otpauth://totp/Acme:alice@example.com?secret=secretKey&issuer=Acme",
				GoogleAuthenticatorQRGenerator.getOtpAuthTotpURL("Acme", "alice@example.com", credentials));

		// issuer and user with spaces
		assertEquals("otpauth://totp/Acme%20Inc:alice%20at%20Inc?secret=secretKey&issuer=Acme+Inc",
				GoogleAuthenticatorQRGenerator.getOtpAuthTotpURL("Acme Inc", "alice at Inc", credentials));

		assertEquals("otpauth://totp/Acme%20&%20%3Cfriends%3E:alice%2523?secret=secretKey&issuer=Acme+%26+%3Cfriends%3E",
				GoogleAuthenticatorQRGenerator.getOtpAuthTotpURL("Acme & <friends>", "alice%23", credentials));
	}

}