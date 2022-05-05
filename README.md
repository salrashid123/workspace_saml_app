## Google Workspace as Identity Provider for your SAML Application


A couple months back a coworker pointed out that your Google Workspace can be used as an _identity provider_ for SAML capable apps you run:

- [Set up your own custom SAML application using SAML-based SSO](https://support.google.com/a/answer/6087519)

What i was familar with all this time was Google Workspace as the _service provider_ which validated a external _identity providers_ `SAML Assertion` (see [googlapps-sso](https://github.com/salrashid123/googlapps-sso))

The thing that was pointed out was the oppsite:  You run an app that is the service provider for something and Google provides the `SAML Assertion`.  Basically the reverse of what I was doing.

This tutorial shows you a trival SAML-enabled application you deploy on your laptop that authenticates a SAML assertion from  your workspace account.

The tutorial only covers `service provider (sp)` initiated login flows

---

### Setup

To use this demo, you'll need access to a test workspace domain and configure a SAML application within that.  

#### Configure Workspace SAML

First navigate to the workspace -> `Groups` section.  Here we will setup a test google group where any member of this group is authorized to use your saml application.

For this demo, i used `user4@esodemoapp2.com` as that single user.

![images/sso_group.png](images/sso_group.png)


Now navigate to workspace -> `Apps` -> `Web and Mobile Apps`  and thenb `add app`, select `custom SAML Application` on the drop down.

Enter the following (you can name it anything, i called it `iamelevate`).

First download the `IdP Metadata` file and save it to the root folder of this repo as `GoogleIDPMetadata.xml`.  This file contains the public cert Workspace will sign the saml assertion with.  Your SSO app will use the public cert to validate the saml assertion presented.

In `Service provider Details` step:

*  `Useraccess`:  
   Select `ssoappgroup` as targets for this app.  
   This will allow any user in that group to use the saml app.

* `ACS`:  `https://localhost.local:5001/saml/acs`  
   This is the callback url for the app you will run locally

* `entityID`: `elevate.cloud.google.com`  
   This is the ID value that will be present in the saml assertion that your app will check


We'll skip attribute mapping but you can inject groups info into the claims sent back (i.e, your applciaton can be made aware of the groups this user is a member of)

In the end, your config step would look something like this:


![images/app_config.png](images/app_config.png)

![images/config.png](images/config.png)

The SSO URL and `idpid` value will ofcourse be different:

![images/metadata.png](images/metadata.png)

#### Start Service Provider

Edit `/etc/hosts/` and add in

```
127.0.0.1  localhost.local
```

This will allow your browser to access the local service provider app we're about to run

Run

```
go run main.go
```

Now in an incognito browser, goto `https://localhost.local:5001/hello`

You'll see a certificate prompt but ignore that (its there because we used a self-signed ca)

you will get redirected _to_ google. 

Internally, the login redirect from your SP applicaton will include a `SAMLRequest=` value which google will use for the redirect later


The inital redirect looks like this

```text
HTTP/2 302 Found
location: https://accounts.google.com/o/saml2/idp?idpid=C023zw3x8&SAMLRequest=nJJPj9owEMW%2FSuQ7ifGGEKxNKgqqirRt0UJ76M3Ys2DJ8aSeyf7pp6%2FIblV64bA3y573G7%2BZd0umC71eDnyK9%2FBrAOLsuQuR9PmhEUOKGg150tF0QJqt3i2%2F3GmVS22IILHHKC4k%2FXVNn5DRYhDZZt0I7yZzd1hUoMraWYCHujZTcLNFXc5UJQ%2BVWbg5mKl0VmQ%2FIJHH2AiVS5FtiAbYRGITuRFKKjWR5UTV%2B%2Blcl5VWdb4oq58iWwOxj4ZH5Ym5J10UxlocIlN%2BRDwGyC12BRbn76vCu%2F6Dd713zUqqm99PN8%2B1yJZ%2Fra4w0tBB2kF69Ba%2B39%2F9owa0JpyQOB9PeibldIQWxpLItm%2FWP%2FrofDxen9PhtYj05%2F1%2BO9l%2B2%2B1FO%2B5Kj8ZT9glTZ%2Fg65Hzj3eRhLNUQ2fOLaCHAo2HIbcDBXUzgtrjgt2%2FB%2BGo62Ky3GLx9eUdPTiaSh8giW4aAT6sEhqERnAYQRfva8v%2F4tX8CAAD%2F%2Fw%3D%3D&RelayState=OrXmkDwb335POGVxU97mySMWMXM0gii6mg_EOhm-pig68hQRhpnRs2Qk

set-cookie: saml_OrXmkDwb335POGVxU97mySMWMXM0gii6mg_EOhm-pig68hQRhpnRs2Qk=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJodHRwczovL2xvY2FsaG9zdC5sb2NhbDo1MDAxL3NhbWwiLCJleHAiOjE2NTExNjgwNzgsImlhdCI6MTY1MTE2Nzk4OCwiaXNzIjoiaHR0cHM6Ly9sb2NhbGhvc3QubG9jYWw6NTAwMS9zYW1sIiwibmJmIjoxNjUxMTY3OTg4LCJzdWIiOiJPclhta0R3YjMzNVBPR1Z4VTk3bXlTTVdNWE0wZ2lpNm1nX0VPaG0tcGlnNjhoUVJocG5SczJRayIsImlkIjoiaWQtN2RiOTZlMjQ4ZGNlZWY4OGExZWQ1OTg0NTI2MGI2YTlkN2VhMTBkYyIsInVyaSI6Ii9oZWxsbyIsInNhbWwtYXV0aG4tcmVxdWVzdCI6dHJ1ZX0.l2Bw0njoCNVn4xNb3FZMTjwzuphpkXLQKgDMLJ9PDsJ7fRF2f5kdMb2U2jebbwsgOIDlcM5F2RT-oGoaYwEHymunKvwg1ED-9d0Twz3GKBNfAlxLqN53MMzJFapSaIOgc_N1I-dTWMCpjIwnvsgbelFU2Fm1RMk_VhqB3sXibhOLvFF-3dnn-tvYB8hhM4ihsMew7D3F5qv0HRDhbQ0bZFy8H2guZBNXOuZRe28c0BFkjDDQX0O2csyqyQifIRI7yH1xaKIKSw0hmQvZXXV9zaEabq3p6hFiRA-bt5J7fDmKeWe2-Vjewn8MwAVWQbXNamZ9wH-UoP3E2WaBbqXFqw; Path=/saml/acs; Max-Age=90; HttpOnly; Secure
content-length: 0
date: Thu, 28 Apr 2022 17:46:28 GMT
```

![images/sp_redirect.png](images/sp_redirect.png)

If  you decode the `SAMLRequest=`, the values are

```xml
<?xml version="1.0" encoding="UTF-8"?>
<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="id-7db96e248dceef88a1ed59845260b6a9d7ea10dc" Version="2.0" IssueInstant="2022-04-28T17:46:28.946Z" Destination="https://accounts.google.com/o/saml2/idp?idpid=C023zw3x8" AssertionConsumerServiceURL="https://localhost.local:5001/saml/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">
   <saml:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">elevate.cloud.google.com</saml:Issuer>
   <samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" AllowCreate="true" />
</samlp:AuthnRequest>
```

The cookie thats set.  thats just a JWT used by the library i'm using here that signs the JWT for itself (using `certs/spsigner.key`)


Anyway, login as the user you configured for the SSO flow.  In my case its `user4@esodemoapp2.com`


Once you login is complete, google will redirct you back to `https://localhost.local:5001/saml/acs` and provide the SAML

![images/idp_redirect.png](images/idp_redirect.png)

The POST data now includes a `SAMLResponse=` value 
![images/idp_post.png](images/idp_post.png)

 which when you decode and inflate looks like

```xml
<?xml version="1.0" encoding="UTF-8"?>
<saml2p:Response xmlns:saml2p="urn:oasis:names:tc:SAML:2.0:protocol" Destination="https://localhost.local:5001/saml/acs" ID="_9dfc02c786ac50f172effed946f27baa" InResponseTo="id-7db96e248dceef88a1ed59845260b6a9d7ea10dc" IssueInstant="2022-04-28T17:47:31.672Z" Version="2.0">
   <saml2:Issuer xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">https://accounts.google.com/o/saml2?idpid=C023zw3x8</saml2:Issuer>
   <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
      <ds:SignedInfo>
         <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
         <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" />
         <ds:Reference URI="#_9dfc02c786ac50f172effed946f27baa">
            <ds:Transforms>
               <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature" />
               <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#" />
            </ds:Transforms>
            <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256" />
            <ds:DigestValue>Xj48I452muuppMg2NwjirWulnJUgtlnEfBusiZLCWms=</ds:DigestValue>
         </ds:Reference>
      </ds:SignedInfo>
      <ds:SignatureValue>ok+kkIdlHGhZwQUExObo3+r4kkedHmr23abbP9sBaTDUPkgFNzT1TJI6ziocvj/OdM/aNgySsX5p
n1BTBfahIb9xCmZr3HqsoRgFHkvzaLxfkpKYgRGIhjg/wQ8dCNPVcycz9UwyfAWgAUvfMUt4tFU6
OKzTfS0TEgoZUm4XMRqyz/p9MrWjo364xRq5VqVsEHvgfDyVz9vSIdYeNKVxGrL3Lp8tDSz0qUaU
yUcIJ/Bycs5F/GUhgL3gZW6PccS9D9OT7xiClSMEwUDzcSMd+Bl46jFHSD855Hil8ya7Daa7P7/8
VIsMmf7krcnG7X7LleaWPBN0jpsTv+AL6XAmWQ==</ds:SignatureValue>
      <ds:KeyInfo>
         <ds:X509Data>
            <ds:X509SubjectName>ST=California,C=US,OU=Google For Work,CN=Google,L=Mountain View,O=Google Inc.</ds:X509SubjectName>
            <ds:X509Certificate>MIIDdDCCAlygAwIBAgIGAYBrtMdFMA0GCSqGSIb3DQEBCwUAMHsxFDASBgNVBAoTC0dvb2dsZSBJ
bmMuMRYwFAYDVQQHEw1Nb3VudGFpbiBWaWV3MQ8wDQYDVQQDEwZHb29nbGUxGDAWBgNVBAsTD0dv
b2dsZSBGb3IgV29yazELMAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWEwHhcNMjIwNDI3
MTU0NzMwWhcNMjcwNDI2MTU0NzMwWjB7MRQwEgYDVQQKEwtHb29nbGUgSW5jLjEWMBQGA1UEBxMN
TW91bnRhaW4gVmlldzEPMA0GA1UEAxMGR29vZ2xlMRgwFgYDVQQLEw9Hb29nbGUgRm9yIFdvcmsx
CzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
MIIBCgKCAQEAzt7rxxR7ZOzyQ98AjOoldAZ1Cu8wuYXs2bUgdHyVOTFayfukNgk7qeiEMEJtyHtl
hpGQfTCq3ojZS25p6tOxWdvPoLQOc9vFUCHDbmv20Zil7mf+y6qO82fV9ewZHakZLQUONKx1LDt7
ZRwDRmuNqMjXTKIX6JIS1I4sFZaptsYCd/kUh0Im2i6zqFch1OVJkd0xyok1XhXc7VDsGRi+TJmN
vx4SppJloGeOo5TACGIQecxvdQPGc2gA15NjgtiwePmI7VCM5ovPQ0n3on4dBpulMoQ5ippPTf5b
/VLW+ZIsZeVVLLHwFEYQnchXK22gmfp6Kz3AHPtre1fXjbQkQwIDAQABMA0GCSqGSIb3DQEBCwUA
A4IBAQCrqO2ZWP6B4uh7oP1wnZlYZL59FXkfwz4i565Njn0iRpL6Nwa63r28cEAtKkbCAnTCywGK
qhRwY3KfXYffxFwrnO6ZjbezkeYdjuZAG1dolFqZ3lohCF51N2fcjUkuJ8PSN8atxABWN/bRjBlT
8gDH/kFd+iUWJ571awVnaXf5uP4IBbYw/M5cVH1ZCuLcIbgaFWgBXH2+wb3XIblZAqX+fq5iD1Y/
5ALRip0aLohKTBc4NWyNSUdcVYg8n5/TXttEFuJTXX8aLN6752vK+ND5cP5bDo3n0JlxvH7Nzu+E
OXD7P+ft4TJrsf+99PCIK1sGbOXOKFs1sxVOWf6VGRtN</ds:X509Certificate>
         </ds:X509Data>
      </ds:KeyInfo>
   </ds:Signature>
   <saml2p:Status>
      <saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" />
   </saml2p:Status>
   <saml2:Assertion xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion" ID="_fc3ee2daa1fa4f9a9f392ab10f33b56a" IssueInstant="2022-04-28T17:47:31.672Z" Version="2.0">
      <saml2:Issuer>https://accounts.google.com/o/saml2?idpid=C023zw3x8</saml2:Issuer>
      <saml2:Subject>
         <saml2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">user4@esodemoapp2.com</saml2:NameID>
         <saml2:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
            <saml2:SubjectConfirmationData InResponseTo="id-7db96e248dceef88a1ed59845260b6a9d7ea10dc" NotOnOrAfter="2022-04-28T17:52:31.672Z" Recipient="https://localhost.local:5001/saml/acs" />
         </saml2:SubjectConfirmation>
      </saml2:Subject>
      <saml2:Conditions NotBefore="2022-04-28T17:42:31.672Z" NotOnOrAfter="2022-04-28T17:52:31.672Z">
         <saml2:AudienceRestriction>
            <saml2:Audience>elevate.cloud.google.com</saml2:Audience>
         </saml2:AudienceRestriction>
      </saml2:Conditions>
      <saml2:AuthnStatement AuthnInstant="2022-04-28T17:47:31.000Z" SessionIndex="_fc3ee2daa1fa4f9a9f392ab10f33b56a">
         <saml2:AuthnContext>
            <saml2:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified</saml2:AuthnContextClassRef>
         </saml2:AuthnContext>
      </saml2:AuthnStatement>
   </saml2:Assertion>
</saml2p:Response>
```

The ACS endpoint will validate/verify the SAML Assertion and then setup a session and cookie for itself (the session and cookie this applciaton sets up is just specific to this and used by this app).

In this case, the acs endpoint will redirect back to the initial `/hello` endpoint originally requested (the sp knows this because of....the cookies it initially set..)

![images/sp_acs_response.png](images/sp_acs_response.png)

This bit is specific to this app...the cookie (`token=`) is really just a JWT signed by the private key `spsigner.key`:

![images/sp_target.png](images/sp_target.png)

```json
{
  "alg": "RS256",
  "typ": "JWT"
}
{
  "aud": "https://localhost.local:5001/saml",
  "exp": 1651171652,
  "iat": 1651168052,
  "iss": "https://localhost.local:5001/saml",
  "nbf": 1651168052,
  "sub": "user4@esodemoapp2.com",
  "attr": {
    "SessionIndex": [
      "_fc3ee2daa1fa4f9a9f392ab10f33b56a"
    ]
  },
  "saml-session": true
}
```

So..finally, your app has a session for the user where the user was authenticated by Google.

The text output for `/hello` will show:

```text
Token contents, {
    StandardClaims:{
        Audience:https://localhost.local:5001/saml 
        ExpiresAt:1651171652 
        Id: 
        IssuedAt:1651168052 
        Issuer:https://localhost.local:5001/saml 
        NotBefore:1651168052 
        Subject:user4@esodemoapp2.com
    } 
    Attributes:map[SessionIndex:[_fc3ee2daa1fa4f9a9f392ab10f33b56a]] SAMLSession:true
    }!
```

>> NOTE: since ths is a demo, once you finish, just delete the SAML App and the group memebership

#### Mapping Groups

You can also define an attribute map for a group which will convey an attribute that defines a set of group the user maybe a member of

Suppose user below is a member of these five groups

```bash
gcloud identity groups memberships search-transitive-groups \
   --labels="cloudidentity.googleapis.com/groups.discussion_forum" \
   --member-email="user4@domain.com" --format=json | jq -r '.memberships[].displayName'

group8_10
group4_7
ssoappgroup
group_of_groups_1
all_users_group
```

if you define an attribute emap like this that says "if the user is a member of these gruops, populate an attribute with those groups as values"

![images/group_mapping.png](images/group_mapping.png)

the resulting map would show one of the values since the user is a member of `ssogroup` and `group4_7`

```xml
<saml2:AttributeStatement>
   <saml2:Attribute Name="mygroups">
      <saml2:AttributeValue 
         xmlns:xs="http://www.w3.org/2001/XMLSchema" 
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
         xsi:type="xs:anyType">
         ssoappgroup
      </saml2:AttributeValue>
      <saml2:AttributeValue 
         xmlns:xs="http://www.w3.org/2001/XMLSchema" 
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" 
         xsi:type="xs:anyType">
         group4_7
      </saml2:AttributeValue>
   </saml2:Attribute>
</saml2:AttributeStatement>
```

##### Decoding SAMLRequest/Response

To decode items, first [urldecode](https://www.urldecoder.org/), then [base64decode](https://www.base64decode.org/), then [saml decode](https://www.samltool.com/decode.php), finally [prettyprint](https://www.freeformatter.com/xml-formatter.html#ad-output)

