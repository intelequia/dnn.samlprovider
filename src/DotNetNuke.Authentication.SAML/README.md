# DotNetNuke.Authentication.SAML
SAML 2.0 Authentication Provider

A free, open source authentication provider for DNN, forked from https://github.com/AccordLMS/AccordLMS.SAML

You can now Single Sign On from a remote website (if it has implemented SAML) to your DNN Portal.

## SAML
https://en.wikipedia.org/wiki/Security_Assertion_Markup_Language
Security Assertion Markup Language (SAML) is an open standard for exchanging authentication and authorization data between parties, in particular, between an identity provider and a service provider. SAML is an XML-based markup language for security assertions (statements that service providers use to make access-control decisions). SAML is also:

A set of XML-based protocol messages
A set of protocol message bindings
A set of profiles (utilizing all of the above)
The single most important use case that SAML addresses is web browser single sign-on (SSO). Single sign-on is relatively easy to accomplish within a security domain (using cookies, for example) but extending SSO across security domains is more difficult and resulted in the proliferation of non-interoperable proprietary technologies. The SAML Web Browser SSO profile was specified and standardized to promote interoperability.

https://en.wikipedia.org/wiki/Identity_provider_(SAML)
A SAML identity provider is a system entity that issues authentication assertions in conjunction with a single sign-on (SSO) profile of the Security Assertion Markup Language (SAML).

In the SAML domain model, a SAML authority is any system entity that issues SAML assertions.[OS 1] Two important examples of SAML authorities are the authentication authority and the attribute authority.

Available at GitHub
https://github.com/intelequia/dnn.samlprovider

## Current Features
- Single Sign On to a DNN site from a remot site using a SAML identity provider
- Match your DNN Profile properties and User properties with SAML Claims
- Sync these values during a User login 
- Creates and Syncs a new DNN User during login if it doesn't exist
- Can assign users to roles identified in an incoming SAML Attribute.  (Creating roles as needed in DNN as well)
- Can remove a user from roles if they are not included in the passed SAML Attribute

* Minimum DNN Version *

DNN 9.3.2 and later supported

# Generating a self-signed certificate with OpenSSL
```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365
```

This other version generates a 10 years certificate and does not prompt for any information
```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"
```

