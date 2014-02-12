package com.warrenstrange.googleauth;


import org.junit.Test;

/*
 * Not really a unit test- but it shows usage
 */
public class GoogleAuthTest {

    @Test
    public void genSecretTest() {
        GoogleAuthenticator gauth = new GoogleAuthenticator();

        final GoogleAuthenticatorKey key = gauth.generateSecretKey();
        final String secret = key.getKey();

        String url = GoogleAuthenticatorKey.getQRBarcodeURL("testuser", "testhost", secret);

        System.out.println("Please register " + url);
        System.out.println("Secret key is " + secret);
    }


    // Change this to the saved secret from the running the above test.
    static String savedSecret = "VV5OVNP4S42DQSS3";

    @Test
    public void authTest() {
        // enter the code shown on device. Edit this and run it fast before the code expires!
        int code = 863311;

        GoogleAuthenticator ga = new GoogleAuthenticator();
        ga.setWindowSize(5);  //should give 5 * 30 seconds of grace...

        boolean r = ga.authorize(savedSecret, code);

        System.out.println("Check code = " + r);
    }


}
