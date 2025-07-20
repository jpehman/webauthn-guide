# <a id="registrationCeremony"></a> The Registration Ceremony

Before you can get started with the registration of a device, you need to make sure that the device has WebAuthn features available.

```javascript
  const available = await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
```

If `available` returns `false`, then you can quit early, because there's no way to use WebAuthn on the device.

Otherwise, you can move to the registration `challenge` request.

### <a id="registrationChallenge"></a> Challenge
In our implementation of WebAuthn, each ceremony requires user initiation. We went this route to avoid surprising long standing users with unwanted prompts. In any case, the first request made by the client is to the server for a `challenge`.

In our case, the request to the `WorldClientAPI` looks like this:
```javascript
  let challengeJSON = await fetch(`${host}/authenticate/credentials/register/challenge`);
```

You may be wondering, "how does the server respond here?"

That is an excellent question, and the primary reason I decided to write this guide. This was the one question that it was difficult to find answers to during my research of WebAuthn, because it is "outside the scope of the specification."

Now, let's get to it.

On the server, we decided to only accept this request if the user was already signed in with an active session. This does a few things for us. First, invalid requests receive a 404 error before there is any opportunity for a data leak. Second, we are reasonably sure that we have a valid user name and host (hacked accounts notwithstanding). Lastly, we will not be troubled by whether or not the device belongs to the user in question.

Once we have the `userid` (which is an email address in our case), the user's name, and the host which the user is making the request from we can start building our `challenge`.

```json
  {
    "attestation": "none",
    "challenge": "9nwYVw2rwD5R0naBxxJT9A0GnKK5e3Fkl0nR0s4r4Ng=",
    "rp": {
      "id": "example.com",
      "name": "Example Technologies, Ltd.",
    },
    "user": {
      "id": "rVqVThBczS+xnuCv8Y//X1obmeAm6KEnYXTDtgWrRCI=",
      "name": "john.doe@example.com",
      "displayName": "John Doe"
    },
    "timeout": 12000, /*2 minutes*/
    "pubKeyCredParams": [
      {
        "alg": -7, /*ES256*/
        "type": "public-key"
      },
      {
        "alg": -257, /*RS256*/
        "type": "public-key"
      }
    ],
    "authenticatorSelection": {
      "residentKey": "preferred",
      "requireResidentKey": false,
      "userVerification": "required"
    },
    "excludeCredentials": [
      {
        "id": "VDz/n9ZC0ijddXn89FM18snB9BQhDLDi+Yhoo2LBTsE=",
        "transports": ["usb", "ble", "nfc", "internal"],
        "type": "public-key"
      }
    ],
    "extensions": []
  }
```

Let's talk about all these properties in the `challenge`.

`attestation` defaults to `none` in the case that you do not include it in your `challenge`. As of the writing of this guide, the other options are `packed`, `tpm`, `android-key`, `android-safetynet`, `fido-u2f`, and `apple`. The full list can be found at [https://www.iana.org/assignments/webauthn/webauthn.xhtml](https://www.iana.org/assignments/webauthn/webauthn.xhtml).

The purpose of the `attestation` format is to allow the Relying Party to further verify the authenticity of the device attempting to register as an authenticator. Each option comes with its own method of verification which can be further researched at the same link where the list is found. It is not within the scope of this guide to explain each of these options further. Suffice it to say, it involves parsing X.509 certifcates and making HTTPS requests to Certificate Authorities.

### <a id="challengeId"></a> `challenge` bytes

`challenge.challenge` must be a cryptographically random number at least 16 bytes in length. You will notice that the `challenge.challenge` and `id`s above are all base64 encoded, so that they can be sent over HTTPS connections with ease.

### <a id="rpObject"></a> `relying party` object

`rp` is short for relying party. The `rp` object consists of two properties. The `id` is a host address (no port included), and the `name` should be self explanatory.

### <a id="userObject"></a> `user` object

`user` is an object consisting of three properties. The `id` must be a cryptographically random number at least 16 bytes in length. It will be returned as the `userHandle` from `navigator.credentials.get` when going through the authentication ceremony. The `name` should be a user name and not an email address if at all possible (according to the spec), but seeing as how our product is an email server there was no real choice for us. The `displayName` should be the user's actual name. Both the `name` and the `displayName` can be used by the authenticator device when interacting with the user.

### <a id="timeoutValue"></a> `timeout` value

`timeout` is how much time in milliseconds the relying party will allow before the `challenge` is no longer valid and any response that includes the `challenge` will be rejected.

### <a id="validAlgorithms"></a> `pubkeyCredParams` array

`pubKeyCredParams` tells the authenticator which signature algorithms the relying party will be able to verify. The ES256 and RS256 algorithms are generally expected to be present. However, as of the writing of this guide, Chrome's WebAuthn testing tool only handles ES256. The remaining possible algorithms are as follows: 
- ES384: -35
- ES512: -36
- RS384: -258
- RS512: -259
- PS256: -37
- PS384: -38
- PS512: -39

From what I have been able to gather, the only relevent difference between RS and PS is the padding type being used. PKCS1 for RS, and PSS for PS. Your cryptographic library should have those padding types available if you wish to implement more than the basic algorithms.

`authenticatorSelection` has four possible properties, `authenticatorAttachment`, `residentKey`, `requireResidentKey`, and `userVerification` ([https://www.w3.org/TR/webauthn/#dictdef-authenticatorselectioncriteria](https://www.w3.org/TR/webauthn/#dictdef-authenticatorselectioncriteria)).

`authenticatorAttachment` is either "platform" or "cross-platform" ([https://www.w3.org/TR/webauthn/#enum-attachment](https://www.w3.org/TR/webauthn/#enum-attachment)). If it's empty or undefined as above, the authenticator will not filter out options based on this value.

`residentKey` is either "preferred", "required", or "discouraged" ([https://www.w3.org/TR/webauthn/#enum-residentKeyRequirement](https://www.w3.org/TR/webauthn/#enum-residentKeyRequirement)).  

`requireResidentKey` is a boolean value. This value overrides the `residentKey` in the case of a `true` value.

`userVerification` is either "required", "preferred", or "discouraged" ([https://www.w3.org/TR/webauthn/#enum-userVerificationRequirement](https://www.w3.org/TR/webauthn/#enum-userVerificationRequirement)). 

`excludeCredentials` consists of an array of credentials ([https://www.w3.org/TR/webauthn/#dictionary-makecredentialoptions](https://www.w3.org/TR/webauthn/#dictionary-makecredentialoptions)). If the authenticator finds the credentials on the device, then it will not allow the user to add an additional credential for the device.
<em>This array should never be empty, otherwise it could reveal the existence or non-existence of the given user. Instead, you should make sure that it always returns at least one credential with consistent `id`, `type` and `transports` values.</em>

<a id="excludeCredentials"></a>

```javascript
  if (challengeJSON.excludeCredentials.length < 1) {
    // a salt value that is created one time and then stored for future use
    const salt = getSalt(); 
    const excludeCredential = {
      transports: ["usb", "nfc", "ble", "internal"],
      type: "public-key",
    };

    const hashId = sha256Hash(user + salt);
    excludeCredential.id = base64Encode(decodeHex(hashId));
    challengeJSON.excludeCredentials.push(excludeCredential);
  }
```

`extensions` consists of an array of optional WebAuthn client extensions ([https://www.w3.org/TR/webauthn/#webauthn-extensions](https://www.w3.org/TR/webauthn/#webauthn-extensions))

After you have created the challenge, be sure the server stores it for at least as long as the `timeout` suggests.

Having a challenge cleanup method of some kind would also be prudent.

### <a id="registrationClientChallenge"></a> Client Side Challenge Response Handling
Assuming the `challenge` is returned, each base64 encoded random value has to be converted to an `ArrayBuffer` before being submitted to `navigator.credentials.create`.

For example:
```javascript
  // make sure this method can handle base64url, and utf8 decoding 
  // we use https://www.npmjs.com/package/base64util because it handles utf8 while a lot of other libraries do not

  const str = base64Decode(challengeJSON.challenge); 
  const buffer = new ArrayBuffer(str.length);
  const byteView = new Uint8Array(buffer);
  for (let i = 0; i < str.length; i++) {
    byteView[i] = str.charCodeAt(i);
  }

  challengeJSON.challenge = buffer;
  // then do the same for challengeJSON.user.id and all challengeJSON.excludeCredentials ids
```

Once the ids are converted to `ArrayBuffer`s you can make the request to the credentials object.

```javascript
  const pubKeyCredential = await navigator.credentials.create(
    { publicKey: challengeJSON }
  );
```
At this point, the device presents an authentication dialog to the user. If the user has a security key, a pass key feature, or a biometric feature, then the user produces the necessary input to the device and a `challenge` response is returned. The user could also cancel the ceremony at this point.

### <a id="clientSideAttestationResponse"></a> Client Side Attestation Response Handling
Now that we have our `challenge` response from the authenticator, we need to test it, make some minor edits, and send the response to the server.

```javascript
  // make sure that the response is an instance of AuthenticatorAttestationResponse
  if (pubKeyCredential && pubKeyCredential.response && pubKeyCredential.response instanceof window.AuthenticatorAttestationResponse)
  {
    // create a new object to send to the server, because you have to convert the ArrayBuffers back to base64 encoded values
    const credentialJSON = {};
    credentialJSON.authenticatorAttachment = pubKeyCredential.authenticatorAttachment;
    credentialJSON.credentialId = base64urlToBase64String(pubKeyCredential.id);
    credentialJSON.response = {
      attestationObject: bufferToBase64(pubKeyCredential.response.attestationObject),
      clientDataJSON: bufferToBase64(pubKeyCredential.response.clientDataJSON)
    };

    if (typeof pubKeyCredential.getClientExtensionResults === "function") {
      credentialJSON.clientExtensionResults = pubKeyCredential.getClientExtensionResults();
    }

    if (typeof pubKeyCredential.response.getTransports === "function") {
      credentialJSON.transports = pubKeyCredential.response.getTransports();
    }

    // the WorldClientAPI request looks like this
    const response = await fetch(`${host}/authenticate/credentials/register`, { method: "POST" });
  }
```

Below are some sample methods for `base64urlToBase64String` and `bufferToBase64`

```javascript
  function bufferToBase64(buffer) {
    const byteView = new Uint8Array(buffer);
    let str = "";
    for (const charCode of byteView) {
      str += String.fromCharCode(charCode);
    }
    return byteEncode(str);
  }

  function base64urlToBase64String(base64urlString) {
    const padding = "==".slice(0, (4 - base64urlString.length % 4) % 4);
    return base64urlString.replace(/-/g, "+").replace(/_/g, "/") + padding;
  }
```

### <a id="serverSideAttestationResponse"></a> Server Side Attestation Response Handling

Now for the hard part. The Attestation Response object must now be validated before the user can be considered to be registered.

Here's how the attestation should look coming into your validation method:
```json
  /* This is an actual result that you could potentially use to examine the details of CBOR decoding. But don't worry, it's only a test user on a test server. No real world application.*/
  {
    "authenticatorAttachment": "platform",
    "clientExtentionResults": {},
    "credentialId": "DaXL6iGmca5Vh74QAMrXHUIynXC7KH96L7LVw7iZUnc=",
    "response":{
      "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVikKMyPOnEP9NAjxFjG45c9ECNSjgfKCwKn3HyloWYAGdVFAAAAAQECAwQFBgcIAQIDBAUGBwgAIA2ly+ohpnGuVYe+EADK1x1CMp1wuyh/ei+y1cO4mVJ3pQECAyYgASFYIFtlIUDmZmTQ9MfhTKVyibC6QPe8s5dbWU9iao+IDrWzIlgg4bxi/s4+J9t6I2Mt16dkZxasuqbo0KVAyVCO1zVUO1o=",
      "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiN0YxYmNqd2xNU1hfRU9ybkRrdWtWaGVNWFNfQnQ2MzlORElLUG93a1pkTVEyeDBZNF92Rmh3elVYUEljQnpTejdBei1xcEpwbE1aNWRNUDhweVhVRGciLCJvcmlnaW4iOiJodHRwczovL21haWwuamVkaS50ZXN0IiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ=="
    },
    "transports": ["internal"],
    "type":"public-key",
  }
```
Here's the spec's overview of this material, which you may find helpful for filling in some of the gaps in this guide: [https://www.w3.org/TR/webauthn/#sctn-attestation](https://www.w3.org/TR/webauthn/#sctn-attestation)

If any of the following steps fails, return an error.

### Validation of the `clientDataJSON`
- Base64 decode the `clientDataJSON`. 
  - You now have a UTF8 encoded JSON string. This might be fine normally, but we need it in ASCII so convert it.
- Once it is in ASCII, use a JSON parser on it and confirm that it's valid JSON before moving on.
- Verify the `challenge` which you find in `clientDataJSON.challenge` matches the registration challenge that you stored previously.
- Verify the `clidentDataJSON.type` value is equal to "webauthn.create"
- Validate the origin. This value includes the protocol, host, and port (if it's not 80 or 443). 

For example:
```javascript
  const hostOrigin = "https://www.example.com:888";
  if (hostOrigin !== clientDataJSON.origin) {
    // return an error
  }
```

- (The spec says you are supposed to sha256 hash the `clientDataJSON`. I found no where else that the hash value is being used, so feel free to skip this step.)

### <a id="attestationObjectValidation"></a> Validation of the `attestationObject`
- Base64 decode the attestationObject using a method that will continue to output data even after the end of a null terminated string. (This was an issue for C++)
- Using a CBOR library (you may have to test with several libraries, because some are unforgiving), get the `fmt`, `attStmt`, and `authData` variables from the CBOR object.
- Get `fmt` as a string and verify that its value matches `challenge.attestation`.
- Verify that `authData` is a byte string.
- Get `authData` as a string
  - `authData` should be in the form of a base64url, so decode it
  - retrieve the first 32 bytes and assign them to a string named something like `rpIdHash`
  - hex encode `rpIdHash`
  - Verify that the sha256 hash of `challenge.rp.id` matches the `rpIdHash`
- Assign the next byte of `authData` to your coding language equivalent of an unsigned char named `flagByte`
  - Both the UP (User Present) and UV (User Verified) bytes need to be true
```javascript
  const UP = (flagByte & 1) != 0;
  const UV = (flagByte & 4) != 0;
```
- Assign the next 4 bytes to the `signCount`.
  - It's big endian, so you need to shift it into an unsigned int. You will use it later
- Assign the next 16 bytes to a string called `aaGuid`
  - Base64 encode the `aaGuid`
- Assign the next 2 bytes to the `credentialIdLength` and shift it into an unsigned int.
- Use the `credentialIdLength` to assign the next byte + the length of the credential to a string called `credentialId` and base64 encode this value
- Assign that same byte + length to a string called `credentialPublicKey` (do not encode it)
- <a id="credentialPublicKeyValidation"></a>Use a CBOR library to decode the `credentialPublicKey`
  - Get property `3` and verify that its value is a long long
    - This value is the type of signing algorithm being used
    - Verify that it's a valid algorithm option as listed here: [Valid Algorithms](#validAlgorithms)
    - Verify that it's an algorithm you included in your supported list
  - Get property `1`, it should be either "2" to represent ES, or "3" to represent RS and PS
  - If property `1` is "2", get property `-2` and property `-3`
    - `-2` and `-3` are base64url encoded strings of the two parts of the ECDSA public key, decode each of them into separate variables
    - They should each be 32 bytes in length decoded 
    - Use whatever ECDSA signer library you can find to verify that the decoded public key is a valid key for signing
  - If property `1` is "3", get property `-1` and property `-2`
    - `-1` is the modulus and `-2` is the exponent, and both are base64url encoded
    - Use whatever RSA signer library you can find to verify that the decoded modulus and exponent make a valid key for signing

Assuming everything above succeeds, you will need to store the following properties for the [Authentication Ceremony](authentication.md)
  - `credentialPublicKey`
  - `signCount`
  - `transports`
  - `userId`
  - `rpId`

  