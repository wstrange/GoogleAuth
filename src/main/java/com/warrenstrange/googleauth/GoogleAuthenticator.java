package com.warrenstrange.googleauth;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base32;

/**
 * Java Server side class for Google Authenticator's TOTP generator 
 * Thanks to Enrico's blog for the sample code:
 * @see http://thegreyblog.blogspot.com/2011/12/google-authenticator-using-it-in-your.html 
 * 
 * 
 * @see http://code.google.com/p/google-authenticator 
 * @see http://tools.ietf.org/id/draft-mraihi-totp-timebased-06.txt
 */
public class GoogleAuthenticator {
		
	// taken from Google pam docs - we probably don't need to mess with these
	final static int secretSize = 10;
	final static int numOfScratchCodes = 5;
	final static int scratchCodeSize = 8;
	
	int window_size =3;  // default 3 - max 17 (from google docs)
	
	/**
	 * set the windows size. This is an integer value representing the number of 30 second windows we allow
	 * The bigger the window, the more tolerant of clock skew we are. 
	 * 
	 * @param s window size - must be >=1 and <=17.  Other values are ignored
	 */
	public void setWindowSize(int s) {
		if( s >= 1 && s <= 17 )
			window_size = s;
	}

	/**
	 * Generate a random secret key. This must be saved by the server and associated with the 
	 * users account to verify the code displayed by Google Authenticator. 
	 * The user must register this secret on their device. 
	 * @return secret key
	 */
	public static String generateSecretKey() {
		// Allocating the buffer
		byte[] buffer = new byte[secretSize + numOfScratchCodes* scratchCodeSize];

		// Filling the buffer with random numbers.
		// Notice: you want to reuse the same random generator
		// while generating larger random number sequences.
		new Random().nextBytes(buffer);

		// Getting the key and converting it to Base32
		Base32 codec = new Base32();
		byte[] secretKey = Arrays.copyOf(buffer, secretSize);
		byte[] bEncodedKey = codec.encode(secretKey);
		String encodedKey = new String(bEncodedKey);
		return encodedKey;
	}

	/**
	 * Return a URL that generates and displays a QR barcode. The user scans this bar code with the
	 * Google Authenticator application on their smartphone to register the auth code. They can also manually enter the
	 * secret if desired
	 * 
	 * @param user   user id (e.g. fflinstone)
	 * @param host   host or system that the code is for (e.g. myapp.com)
	 * @param secret the secret that was previously generated for this user
	 * @return the URL for the QR code to scan
	 */
	public static String getQRBarcodeURL(String user, String host, String secret) {
		String format = "https://www.google.com/chart?chs=200x200&chld=M%%7C0&cht=qr&chl=otpauth://totp/%s@%s%%3Fsecret%%3D%s";
		return String.format(format, user, host, secret);
	}

	/**
	 * Check the code entered by the user to see if it is valid
	 * @param secret  The users secret. 
	 * @param code  The code displayed on the users device
	 * @param t  The time in msec (System.currentTimeMillis() for example)
	 * @return
	 */
	public boolean check_code(String secret, long code, long timeMsec) {
		Base32 codec = new Base32();
		byte[] decodedKey = codec.decode(secret);
			
		// convert unix msec time into a 30 second "window" 
		// this is per the TOTP spec (see the RFC for details)
		long t = (timeMsec / 1000L) / 30L;
		// Window is used to check codes generated in the near past.
		// You can use this value to tune how far you're willing to go.
		
		for (int i = -window_size; i <= window_size; ++i) {
			long hash;
			try {
				hash = verify_code(decodedKey, t + i);
			} catch (Exception e) {
				// Yes, this is bad form - but
				// the exceptions thrown would be rare and a static configuration problem
				e.printStackTrace();
				throw new RuntimeException(e.getMessage());
				//return false;
			} 
			if (hash == code) {
				return true;
			}
		}
		// The validation code is invalid.
		return false;
	}

	
	private static int verify_code(byte[] key, long t)
			throws NoSuchAlgorithmException, InvalidKeyException {
		byte[] data = new byte[8];
		long value = t ;
		for (int i = 8; i-- > 0; value >>>= 8) {
			data[i] = (byte) value;
		}

		SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
		Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(signKey);
		byte[] hash = mac.doFinal(data);

		int offset = hash[20 - 1] & 0xF;

		// We're using a long because Java hasn't got unsigned int.
		long truncatedHash = 0;
		for (int i = 0; i < 4; ++i) {
			truncatedHash <<= 8;
			// We are dealing with signed bytes:
			// we just keep the first byte.
			truncatedHash |= (hash[offset + i] & 0xFF);
		}

		truncatedHash &= 0x7FFFFFFF;
		truncatedHash %= 1000000;

		return (int) truncatedHash;
	}
}
