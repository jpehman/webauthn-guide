# A Guide to Basic WebAuthn Implementation
*For Relying Parties and Clients*

In February of 2023, MDaemon Technologies, Ltd. decided to implement WebAuthn for its web facing products.

Through reading the spec, a great deal of trouble shooting, and mountains of help from my boss, we were finally able to complete a basic implementation of WebAuthn.

Hereafter is a guide to implementing WebAuthn from the view of a Relying Party, including code samples, pitfalls, and caveats as needed.

## Table of Contents
- [Requirements](#requirements)
- [Important Links](#importantLinks)
- [Important Terms](#importantTerms)
- [The Registration Ceremony](registration.md#registrationCeremony)
- [The Authentication Ceremony](authentication.md#authenticationCeremony)
- [Security Concerns](security.md#securityConcerns)


## <a id="requirements"></a> Requirements
To begin with, you will need to add a few libraries to your code base. Without them, you will not be able to implement WebAuthn on the server side.

Make sure you have libraries that will do the following:
- base64 encode/decode bytes in the browser (we use [base64util](https://www.npmjs.com/package/base64util))
- base64url encode/decode on server and the browser
- hex encode/decode bytes
- Decode Concise Binary Object Representation ([CBOR](https://cbor.io/))
- Validate ECDSA and RSA public keys
- Verify ES256 and RS256 signatures at a minimum
- Generate cryptographically random numbers of varying lengths
- Handle JSON (if you are not using Node)

HTTPS connections are required for all parts of both ceremonies. You will not be able to test devices without a trusted certificate.

You can get around that a little using localhost and a Chrome based browser (which has built-in WebAuthn testing tools). However, you may need to use a proxy DNS like NextDNS to test on handheld devices.

## <a id="importantLinks"></a> Important Links
- The Specification: [https://www.w3.org/TR/webauthn/](https://www.w3.org/TR/webauthn/#sctn-intro)
- The Registration Ceremony: [https://www.w3.org/TR/webauthn/#sctn-registering-a-new-credential](https://www.w3.org/TR/webauthn/#sctn-registering-a-new-credential)
- The Authentication Ceremony: [https://www.w3.org/TR/webauthn/#sctn-verifying-assertion](https://www.w3.org/TR/webauthn/#sctn-verifying-assertion)
- List of algorithm types: [https://www.iana.org/assignments/cose/cose.xhtml#key-type](https://www.iana.org/assignments/cose/cose.xhtml#key-type)
- A CBOR playground [cbor.me](https://cbor.me/)
- A Base64 and Hex Decoder/Encoder [https://cryptii.com/pipes/hex-decoder](https://cryptii.com/pipes/hex-decoder)
- ECDSA Signature format [https://www.w3.org/TR/webauthn/#sctn-signature-attestation-types](https://www.w3.org/TR/webauthn/#sctn-signature-attestation-types)


## <a id="importantTerms"></a> Important Terms
- Relying Party: The host of the website implementing WebAuthn
- Client: The browser or device used as a proxy between the server and the authenticator device
- Authenticator: The device used for authenticating the user, e.g. a security key, biometric authenticator, or pass key
- registration ceremony: The five part process of creating a valid user public key for use in the authentication ceremony
  - Client - Request a challenge
  - Relying Party - Respond with the challenge
  - Authenticator - Validate the challenge
  - Client - Send the challenge response
  - Relying Party - Validate the challenge response and store the public key
- transports: "A sequence of zero or more unique DOMStrings, in lexicographical order, that the authenticator is believed to support." e.g. ["usb", "nfc", "ble", "internal"]
- CBOR: Concise Binary Object Representation - A binary JSON format that for some reason is only used during the Registration Ceremony (maybe someone thought it was a cool new thing they wanted to learn... I don't know)
- authentication ceremony: The five part process of user validation
  - Client - Request a challenge
  - Relying Party - Respond with the challenge
  - Authenticator - Validate the challenge
  - Client - Send the challenge response
  - Relying Party - Validate the challenge response and... sign the user in or do whatever is needed now that its pretty certain the user is who it says it is
- [ASN.1 Signature Format](https://learn.microsoft.com/en-us/windows/win32/seccertenroll/about-introduction-to-asn-1-syntax-and-encoding): The required format for the public key credential -  Defined by [RFC3279](https://datatracker.ietf.org/doc/html/rfc3279) section 2.2.3
  - Example:
        30 44                                ; SEQUENCE (68 Bytes)
            02 20                            ; INTEGER (32 Bytes)
            |  3d 46 28 7b 8c 6e 8c 8c  26 1c 1b 88 f2 73 b0 9a
            |  32 a6 cf 28 09 fd 6e 30  d5 a7 9f 26 37 00 8f 54
            02 20                            ; INTEGER (32 Bytes)
            |  4e 72 23 6e a3 90 a9 a1  7b cf 5f 7a 09 d6 3a b2
            |  17 6c 92 bb 8e 36 c0 41  98 a2 7b 90 9b 6e 8f 13


