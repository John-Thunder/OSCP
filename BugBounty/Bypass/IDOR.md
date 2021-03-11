# IDOR (Insecure Direct Object References)
https://www.youtube.com/watch?v=3K1-a7dnA60&list=PLF7JR1a3dLONdkRYU_8-5OcgOzrWe2549&index=5

Insecure direct object references (IDOR) are a type of access control vulnerability that arises when an application uses user-supplied input to access objects directly. 

**Example:** 
```
https://insecure-website.com/customer_account?customer_number=132355
```
changing the customer number gets you access to another customers account. 

**Burp Plugins:**
1. authorize - for each request you do it will send an equal request but with something changed (usually the cookie or additional header). 
2. autorepeater - buffed up version of authorize 


## Authorize:
Will need 2 users:
```
User 1 = ADMIN
User 2 = USER
```

1. Turn Burp Proxy on
2. Browse the wbesite with one user
3. Copy all the cookies from the Burp authorize tab and paste them into configuration tab?? on the right side. feel free to add headers as well. 
4. Make sure Interception Filter is on
  - Ignore Spider Requests
  - Only test Scope Items
  - Will IGNORE: \.js|CSS|PNG|JPG|JPEG|GIF|WOFF|MAP|BMP|ICO$
5. Browse site as the other user and Burp will try the cookie of the other user. make sure to try every thing!! click every button, fill in every field, etc. 
6. Check results and Modified response tab to see if you got access. 

**TIP: try the same thing with UUID's that show up in urls**


## Autorepeater: 
1. Edit replacement to tell it what string should be replaced and what it should be replaced with. 
2. Activate autorepeater
3. Browse site and Burp will try the new string for each time the first shows up. make sure to try every thing!! click every button, fill in every field, etc. 
4. Check results and Modified response tab to see if you got access. 

The example given looked for UUID's in urls and replaced them with the UUID from another user, but the attack is not limited to UUIDs. Also is not limited to URLs (Request Strings). in the add replacemnet area you can choose tons of stuff including Request Header, Request Body, Coockie Name, Coockie Value, etc. 
**Consider using for:**
- FALSE -> TRUE
- USER -> ADMIN
- JSON -> XML (will it crash??)






## Looking for high impact IDOR?
https://twitter.com/M0_SADAT/status/1361289751597359105

https://github.com/0xsapra/fuzzparam

Always try to find the hidden parameters for this endpoints using Arjun and Parameth
- /settings/profile
- /user/profile
- /user/settings
- /account/settings
- /username
- /profile
And any payment endpoint
