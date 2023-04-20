# <a id="authenticationCeremony"></a> The Authentication Ceremony

This ceremony can only proceed if the device attempting to authenticate has been registered to a user and the relevant properties have been stored by the Relying Party.

## <a id="authenticationChallenge"></a> Challenge
First request a challenge from the server. In our case, the request to the `WorldClientAPI` looks like this:
```javascript
  let challengeJSON = await fetch(`${host}/authenticate/credentials/auth/challenge`, { method: "POST" });
```

As in the [Registration Ceremony](registration.md#registrationChallenge), the handling of this request is "outside the scope of the specification."

In our case, we only accept a `POST` method for this request, but you can handle it anyway you wish.

Obviously, you need a user name in the request in order to know whether the requester is valid right? Yes. However, you should always respond with a `challenge`. Especially one that a hacker could not use to recognize that the user name sent does or does not exist. 

To achieve this, all `challenge` responses should look the same. Let's have a look at an example.

```json
  {
    "challenge": "9nwYVw2rwD5R0naBxxJT9A0GnKK5e3Fkl0nR0s4r4Ng=",
    "rpId": "example.com",
    "timeout": 12000, /*2 minutes*/
    "allowCredentials": [
      {
        "id": "VDz/n9ZC0ijddXn89FM18snB9BQhDLDi+Yhoo2LBTsE=",
        "transports": ["usb", "ble", "nfc", "internal"],
        "type": "public-key"
      }
    ]
  }
```

The first thing that you may notice is that this object is noticably smaller than the `challenge` from the registration ceremony.

There's also no user identifying information returned.

In the case that the user name sent to the server when requesting the `challenge` is invalid, create an `allowCredentials` value in the same manner that the `excludeCredentials` value was created [here](registration.md#excludeCredentials).

(at the risk of being repetitive)
`challenge.challenge` must be a cryptographically random number at least 16 bytes in length. You will notice that the `challenge.challenge` and `id`s above are all base64 encoded, so that they can be sent over HTTPS connections with ease.

`rpId` must be equivalent to the `rp.id` from the [Registration Challenge](registration.md#rpObject)

`timeout` is how much time in milliseconds the relying party will allow before the `challenge` is no longer valid and any response that includes the `challenge` will be rejected.

`allowCredentials` is an array of credentials that the server will accept. <em>This array should never be empty, otherwise it could reveal the existence or non-existence of the given user. Instead, you should make sure that it always returns at least one credential with consistent `id`, `type` and `transports` values.</em>

### <a id="authenticationClientChallenge"></a> Client Side Challenge Response Handling
Assuming the `challenge` is returned (which should always be the case), each base64 encoded random value has to be converted to an `ArrayBuffer` before being submitted to `navigator.credentials.get`.

For example:
```javascript
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
  const assertion = await navigator.credentials.get(
    { publicKey: challengeJSON }
  );
```

At this point, the device presents an authentication dialog to the user or, if the `transport` is `internal`, use the device to authenticate. The user can either authenticate or cancel the ceremony.

### <a id="clientSideAttestationResponse"></a> Client Side Assertion Response Handling
Now that we have our `challenge` response from the authenticator, we need to test it, make some minor edits, and send the response to the server.

```javascript
  // make sure that the response is an instance of AuthenticatorAssertionResponse
  if (assertion && assertion.response && assertion.response instanceof window.AuthenticatorAssertionResponse)
  {
    // create a new object to send to the server, because you have to convert the ArrayBuffers back to base64 encoded values
    const assertionJSON = {};
    assertionJSON.authenticatorAttachment = assertion.authenticatorAttachment;
    assertionJSON.credentialId = base64urlToBase64String(assertion.id);
    assertionJSON.response = {
      authenticatorData: bufferToBase64(assertion.response.authenticatorData),
      clientDataJSON: bufferToBase64(assertion.response.clientDataJSON),
      signature: bufferToBase64(assertion.response.signature)
    };

    if (typeof assertion.getClientExtensionResults === "function") {
      assertionJSON.clientExtensionResults: assertion.getClientExtensionResults();
    }

    if (assertion.response.userHandle) {
      assertionJSON.response.userHandle = bufferToBase64(assertion.response.userHandle);
    }

    // the WorldClientAPI request looks like this
    const response = await fetch(`${host}/authenticate/credentials/auth`, { method: "POST" });
  }
```

### <a id=""></a> Server Side Assertion Response Handling

Thankfully, the hard part was done during registration. There is no CBOR during the authentication process. 

Here's how the assertion should look coming into your validation method:

```json
  {
    "authenticatorAttachment":"platform",
    "clientExtensionResults":{},
    "credentialId":"0uCz+EaDvksjVBdtufwBiL/A6ihvhDjhQHbb6of1igs=",
    "response": {
      "authenticatorData":"KMyPOnEP9NAjxFjG45c9ECNSjgfKCwKn3HyloWYAGdUFAAAAAg==",
      "clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoicmhwa3VpRDFoTGhKeTdKVVo0clRZRGJVTE5kcHU3VVRjNkZUd0NPZVBZd0M4c29oSTk2YVRnWDkyUjZnQ1ZkdVFZcm8tZEJDYzA4N2RNOWk1NjlwVUEiLCJvcmlnaW4iOiJodHRwczovL21haWwuamVkaS50ZXN0IiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ==",
      "signature":"MEUCIQCWSX+uowgs6aU1Pms1XwFdpYjLhnAkdLV8Jodq4Mn2JgIgXY8/TSfnMrB8ie2jSpzBpqCD5b1YcV3J+70NlWToX5o=",
      "userHandle":"2q3gQgLE1bCUFfvCCzKd21WX/oBnqv0uAKP0O2HjRXQ="
    },
    "type":"public-key"
  }
```

Here's the spec's overview of this material, which you may find helpful for filling in some of the gaps in this guide: [https://www.w3.org/TR/webauthn/#iface-authenticatorassertionresponse](https://www.w3.org/TR/webauthn/#iface-authenticatorassertionresponse)

If any of the following steps fails, return an error.

### Validation of the `clientDataJSON`
- Base64 decode the `clientDataJSON`
  - sha256 hash the result of the decoded `clientDataJSON`, you will use it when verifying the signed data
  - the result is in UTF8, but we need it in ASCII, so convert it
  - You should now have a JSON object that looks something like this:
    ```json
      {
        "type":"webauthn.get",
        "challenge":"rhpkuiD1hLhJy7JUZ4rTYDbULNdpu7UTc6FTwCOePYwC8sohI96aTgX92R6gCVduQYro-dBCc087dM9i569pUA",
        "origin":"https://www.example.com:888",
        "crossOrigin":false
      }
    ```
  - Verify that the `clientDataJSON.type` is "webuthn.get"
  - Verify that the `clientDataJSON.challenge` matches the `challengeJSON.challenge` stored on the server
  - Verify the `clientDataJSON.origin` matches the host

### Validation of the `credentialId`
  - Verify that the `credentialId` exists and corresponds to the user attempting to authenticate
  - Verify that the `credentialId` matches an `allowedCredential` from the `challengeJSON` stored on the server

### Validation of the `authenticatorData`
- Base64 decode the `authenticatorData`
  - assign all the bytes to a `signedData` string
  - decode the hex value of the `clientDataJSON` sha256 hash
  - append the result to the `signedData` string, you will use it later
- Assign the first 32 bytes of `authenticatorData` to `rpIdHash`.
  - Hex encode the value
  - Compare it to the hash of the Relying Party host value (www.example.com)
- Assign the next byte (33rd) to your coding language equivalent of an unsigned char named `flagByte`
  - Like the [Registration Ceremony](registration.md#attestationObjectValidation), the UP (User Present) and UV (User Verified) bytes need to be true
- Assign the next four bytes to a `signCount` variable
  - It's big endian, so you need to shift it into an unsigned int. 
  - Compare it to the stored sign count
  - If it is greater than or equal to the stored sign count, update the stored sign count with the new `signCount`
  - If it is less, then there is a possibility that the previate key was cloned and you should delete the registered public key

### Validation of the `userHandle`
- Compare this to the `challengeJSON.user.id` created during the [Registration Ceremony](registration.md#registrationChallenge)

### Validation of the `signature`
- Retrieve the stored `publicKeyCredential` and validate it in the same way it was done during the [Registration Ceremony](registration.md#credentialPublicKeyValidation)
- Use the public key to verify the `signature`

If the `signature` is valid, the user is authenticated.



