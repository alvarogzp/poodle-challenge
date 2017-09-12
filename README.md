## Challenge description

You are a cryptohacker working for a foreign country security agency. You have currently been assigned to a classified project whose full extent you do not know. Your part consist on accessing NSA private network to steal classified information.

It may sound a hard task, but you are not alone. Your team has already done a good job and have penetrated into several security layers of the NSA network. But they are stuck, and to go further they need to find valid credentials from someone working inside to be able to authenticate themselves and gain more privileges.

They have found a server which seems to provide web access via HTTPS to some kind of credentials-protected storage. The credentials are checked using [Basic HTTP authentication](https://en.wikipedia.org/wiki/Basic_access_authentication). And, the most interesting part is that the server is still using SSLv3! :scream: (maybe an old server they forgot to update).

Your team has also found a desktop computer which is actively talking to that server (ie., sending valid credentials). They have also managed to install a man-in-the-middle (MiTM) software in a router in the path between the computer and the target server.

Now, the only remaining thing that prevents them from getting the credentials is the SSL layer. And there is where you come to action.

Using the MiTM software, they have been able to inject JavaScript code into an insecure web page on the client browser. That JavaScript can perform custom [XHR requests](https://en.wikipedia.org/wiki/XMLHttpRequest) to the target server (with the authentication header being added automatically by the browser).

So, your job is to get the credentials from the SSLv3 encrypted traffic between the browser and the server. Will you be up to it?


### MiTM details

You are only able to perform connections to the MiTM software. That software expects first of all a request to be injected into the client browser. It only support POST requests. You have to specify them in the following format:

    post("/request/path", "csrf=csrf_token&any_query_string");\n

The request path and body can be chosen freely (but you have to include a CSRF token on the body, read below about it).

Then, the MiTM software will send to you all the data that is exchanged between the browser and the server for that request (at the transport level, that is, SSL data).

You will receive the data in the following format:

    X-base64_encoded_data\n

Where X may be either __C__ or __S__ for client-originated data or server-originated data, respectively. Then follows a __-__ character and a base64 encoded string of arbitrary length with the actual data, ending in a newline character.

You can then specify what data gets to the intended destination. No data will be sent without your approval.

You have to specify the data that must be sent in the following format:

    X-base64_encoded_data\n

As you can see, the format is the same as for the incoming data. So, if you do not want to modify it, you can simply send as-is. The data you send with a __C__ as first character will be routed to the server (as you are indicating it is originating from the client), and the data sent with a __S__ as first character will be routed to the client (for the same reason).

If the SSL handshake goes without error, you will get an `ok\n` message.

You can get some error messages from the MiTM, though. If the initial request is not properly formatted, or you do not add a valid CSRF token its body, the request will not be injected and you will be properly notified.

If there is an error in the SSL handshake you will get a `client-error\n` message.


### CSRF token

We will give you a [CSRF](https://en.wikipedia.org/wiki/Cross-site_request_forgery) token which you have to send on the body of the requests you make for them to work (so that we can give different passwords for different users).


### Input

The CSRF token you will have to use on every request you send to the MiTM.


### Output

The `user:password` string encoded in base64 (that is, as the client is sending it to the server).
