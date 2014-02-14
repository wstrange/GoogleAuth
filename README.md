GoogleAuth
==========

Description
-----------

GoogleAuth is a Java server library that implements the Time-based One-time
Password (TOTP) algorithm specified in [RFC 6238][RFC6238].

This implementation borrows from [Google Authenticator][gauth], whose C code has
served as a reference, and was created upon code published in
[this blog post][tgb] by Enrico M. Crisostomo.

Storing User Credentials
------------------------
The library does *not* store nor load user credentials directly, and a hook is
provided to users who want to integrate this functionality.
The *ICredentialRepository* interface defines the contract between a credential
repository and this library and a custom implementation can be plugged in and
used by the library as a user-provided credential repository.

The following methods take a user name as a parameter and require a credential
repository to be available:

* `String getSecretKey(String userName)`.
* `void saveUserCredentials(String userName, ...)`.

### Registering a Credential Repository
The library looks for instances of this interface using the
[Java ServiceLoader API][serviceLoader] (introduced in Java 6), that is,
scanning the `META-INF/services` package looking for a file named
`com.warrenstrange.googleauth.ICredentialRepository` and, if found, loading the
providers listed therein.

Client Applications
-------------------
Both the Google Authenticator client applications (available for iOS, Android
and BlackBerry) and its PAM module can be used to generate codes to be validated
by this library.

However, this library can also be used to build custom client applications if
Google Authenticator is not available on your platform or if it cannot be used.

Library Documentation
---------------------
This library includes full JavaDoc documentation and a JUnit test suite that can
be used as example code for most of the library purposes.

Usage
-----
The following code creates a new set of credentials for a user. No user name is
provided to the API and it's responsibility of the caller to save them for later
use during the authorisation phase.

    GoogleAuthenticator gAuth = new GoogleAuthenticator();
    final GoogleAuthenticatorKey key = gAuth.createCredentials();

The following code creates a new set of credentials for the user `caller` and
stores them on the configured `ICredentialRepository` instance:

    GoogleAuthenticator gAuth = new GoogleAuthenticator();
    final GoogleAuthenticatorKey key = gAuth.createCredentials("caller");

If a credential repository is not configured the code will *fail* throwing an
`UnsupportedOperationException`.

The following code checks the validity of the specified `code` against the
provided Base32-encoded `secretKey`:

    GoogleAuthenticator gAuth = new GoogleAuthenticator();
    boolean isCodeValid = gAuth.authorize(secretKey, code);

The following code checks the validity of the specified `code` against the
secret key of the user `caller` returned by the configured
`ICredentialRepository` instance:

    GoogleAuthenticator gAuth = new GoogleAuthenticator();
    boolean isCodeValid = ga.authorizeUser("caller", code);

[RFC6238]: https://tools.ietf.org/html/rfc6238
[gauth]: https://code.google.com/p/google-authenticator/
[tgb]: http://thegreyblog.blogspot.com/2011/12/google-authenticator-using-it-in-your.html?q=google+authenticator
[serviceLoader]: http://docs.oracle.com/javase/6/docs/api/java/util/ServiceLoader.html