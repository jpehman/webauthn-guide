# <a id="securityConcerns"></a> Security Concerns

According to the spec, there are a few security concerns to consider when implementing WebAuthn.
[WebAuthn Security Considerations](https://www.w3.org/TR/webauthn/#sctn-security-considerations)

Here are some highlights
- "Simplistic use of WebAuthn in an embedded context, e.g., within iframes as described in § 5.10 Using Web Authentication within iframe elements, may make users vulnerable to UI Redressing attacks, also known as 'Clickjacking'".
- Replay attacks 
  - Mitigated by always using cryptographically random values for the `challenge`
- Man-in-the-middle attacks
  - There's no way to know that an attestation statement was not produced by someone other than the intended party during registration
- A user could potentially get locked out of an account if the user loses the authenticator device
- User data leaks
  - As mentioned for `allowCredentials` and `excludeCredentials`, there is potential for the existence or non-existence of a user to be exposed if empty arrays are presented in the `challengeJSON`