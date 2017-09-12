Challenge description
---------------------

You are a cryptohacker working for a foreign country security agency. Your mission is to infiltrate on a NSA data repository cluster to search for a specific USA-government classified document which is of interest to your country.

It may sound a hard task, but you are not alone. Your team has already done a good job and have penetrated into several security layers of the NSA network. They have managed to find a server that looks like an endpoint of some kind of document storage.

This server has a service which is accessible via SSL and seems to provide access to the stored documents. Unfortunately, the access is protected by [HTTP authentication](https://en.wikipedia.org/wiki/Basic_access_authentication). But, the most interesting part is that the server is using SSLv3! :scream: (maybe you should give them more money, Mr. Trump ;)

Your team has also found a desktop computer with a web browser opened which is actively using the service (ie., it has valid credentials). They have also managed to install a man-in-the-middle software in a router in the path between the computer and the target server.

Using that software, they have been able to inject JavaScript code into an insecure web page on the client browser. That JavaScript can perform custom [XHR](https://en.wikipedia.org/wiki/XMLHttpRequest) requests to the target server (with the authentication header being added automatically by the browser).

So, they now need your help. You have told them before about vulnerabilities found on SSLv3 like [POODLE](https://en.wikipedia.org/wiki/POODLE). Would you be able to put that in practice and give them the credentials they need?


MiTM details
------------

You are only able to perform connections to the MiTM software. That software expects first of all a request to be injected into the client browser. It only support POST requests. You have to specify them in the following format:

    post("/request/path", "csrf=csrf_token&any_query_string");\n

The request path and body can be chosen freely (but you have to include a CSRF token on the body, read below about it).

Then, the MiTM software will send to you all the data that is exchanged between the browser and the server for that request (at the transport level, that is, SSL data).

You will receive the data in the following format:

    X-base64_encoded_data\n

Where X may be either *C* or *S* for client-originated data or server-originated data, respectively. Then follows a *-* character and a base64 encoded string of arbitrary length with the actual data, ending in a newline character.

You can then specify what data gets to the intended destination. No data will be sent without your approval.

You have to specify the data that must be sent in the following format:

    X-base64_encoded_data\n

As you can see, the format is the same as for the incoming data. So, if you do not want to modify it, you can simply send as-is. The data you send with a *C* as first character will be routed to the server (as you are indicating it is originating from the client), and the data sent with a *S* as first character will be routed to the client (for the same reason).

If the SSL handshake goes without error, you will get an `ok\n` message.

You can get some error messages from the MiTM, though. If the initial request is not properly formatted, or you do not add a valid CSRF token its body, the request will not be injected and you will be properly notified.

If there is an error in the SSL handshake you will get a `client-error\n` message.


CSRF token
----------

We will give you a [CSRF](https://en.wikipedia.org/wiki/Cross-site_request_forgery) token which you have to send on the body of the requests you make for them to work (so that we can give different passwords for different users ;).


Input
-----

The CSRF token you will have to use on every request you send to the MiTM.


Output
------

The `user:password` string encoded as base64 (that is, as the client is sending it to the server).
