## Challenge description

You are a cryptohacker working for a foreign country security agency. You have currently been assigned to a classified project whose full extent you do not know. Your job consist on accessing NSA private network to steal classified information.

It may sound a hard task, but you are not alone. Your team has already done a good job and have penetrated into several security layers of the NSA network. But they are stuck, and to go further they need to find valid credentials from someone working inside to be able to authenticate as him and gain more privileges.

They have found a server which seems to provide web access via HTTPS to some kind of credentials-protected storage. The credentials are checked using [Basic HTTP authentication](https://en.wikipedia.org/wiki/Basic_access_authentication). And, the most interesting part is that the server is still using SSLv3! :scream: (maybe an old server they forgot to update).

Your team has also found a desktop computer which is actively talking to that server (ie., sending valid credentials). They have also managed to install a man-in-the-middle (MiTM) software in a router in the path between that computer and the target server.

Now, the only remaining thing that prevents them from getting the credentials is the SSL layer. And there is where you come to action.

Using the MiTM software, they have been able to inject JavaScript code into an insecure web page on the client browser. That JavaScript can perform custom [XHR requests](https://en.wikipedia.org/wiki/XMLHttpRequest) to the target server (with the authentication header being added automatically by the browser).

So, your job is to get the credentials from the SSLv3 encrypted traffic between the browser and the server. Will you be up to it?


#### MiTM details

You are only able to perform connections to the MiTM software. That software expects first of all a request to be injected into the client browser. It only support POST requests. You have to specify them in the following format:

    post("/request/path", "csrf=csrf_token&body_query_string");\n

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

You can get some error messages from the MiTM, though. If the initial request is not properly formatted, or you do not add a valid CSRF token to its body, the request will not be injected and you will be properly notified.

If there is an error in the SSL handshake, you will get a `client-error\n` message.


### CSRF token

We will give you a [CSRF](https://en.wikipedia.org/wiki/Cross-site_request_forgery) token which you have to send on the body of the requests you make for them to work (so that we can give different passwords for different users).


### Input

The CSRF token you will have to use on every request you send to the MiTM.


### Output

The `user:password` string encoded in base64 (that is, as the client is sending it to the server).


## Instructions for solving

In order to solve the challenge, you need to contact the MiTM. Currently, we have no one publicly deployed, but you can run it locally.

Just execute the `daemon/daemon.py` script with a Python 2 interpreter with the working directory set on `daemon/`. It will listen for incoming connections on the `4747` port.

Then pick one CSRF from the `test/` or `submit/` `inputX` files, and try to solve it!

You have achieved it when you can successfully obtain the corresponding `outputX` content from the inputX one, using only the MiTM service to get it.

NOTE: If the daemon does not start, see the [Daemon caveats](#daemon-caveats) section below for troubleshooting.

Do not keep reading if you are planning to solve the challenge, otherwise you may end up with key information for solving and it will be less challenging.


---
---


## Repository structure

First, there is a `daemon/` directory. There is all needed to run the challenge server.

The `daemon.py` contains the code that simulates the MiTM. It accepts connections on a public port, and performs a fake client-server communication with a proxy in the middle that allows external modifications to the exchanged data.

The `.pem` files contain a fake NSA certificate and private key to make it more realistic.

And the `tokens` file allows to map CSRF tokens to credentials.

The `test/` and `submit/` directories contain _input -> output_ mappings to allow automatic validation of challenge submissions. They, along with the daemon tokens file can be automatically generated with random values using `gen_inputs_outputs_tokens.sh`.

Finally, the `solution/` directory contain the proposed solution that were created while developing the challenge.


## Daemon caveats

In order for the challenge to be feasibly solved as it was proposed, the daemon script must be run under the following conditions:

 - The Python interpreter must have been compiled and run with an underlying ssl library that has SSLv3 support enabled. Otherwise, it will fail to properly startup. Recent ssl libraries versions ship with SSLv3 disabled to avoid insecure connections. If it seems to be your case, you might need to tweak and compile the ssl library and Python for yourself (or try to run the daemon on an older operating system version).

 - The peers must negotiate a `null` compression algorithm. If you use Python version 2.7.9 or newer, the daemon takes care of it. But on older Python versions, there is no way to tell the ssl layer to not use compression at all. If you use Python 2.7.8 or lower, please check that no compression algorithm is being used before trying to solve the challenge (you can do it by running a network analyzer on the loopback interface), and if any algorithm is being used, update to a newer Python version. Although with a compression algorithm the challenge may still be resolved, it would be much more complex.


---
---


## Context and explanation

This challenge was made for inclusion into the Tuenti Challenge 2015, but it finally did not get into it.

It exploits the [POODLE](https://en.wikipedia.org/wiki/POODLE) vulnerability of SSLv3 to retrieve the HTTP Authorization header (it could have been a cookie also). See also [this](https://www.openssl.org/~bodo/ssl-poodle.pdf) for technical details of the vulnerability.

In order to do it, first the request length must be adjusted to have a full block of padding at the end. This can be achieved by modifying the request path length and looking at the SSL handshake to see when the final data packet gets larger.

Then, using the technique described in the previous link, the last plaintext byte of a given encrypted block can be obtained by replacing the full-padding block with a selected block and seeing if the server accepts it.

If it does, then the plaintext last byte of the selected block can be easily obtained by XORing the encrypted byte with the corresponding byte on the previous-to-last block and the corresponding byte on the previous-to-selected block. If the server rejects the data, then it can be tried again until it is accepted (there is a 1/256 probability).

By modifying the path and body length simultaneously so that the request still have a full padding block and selecting the proper block to decrypt its final byte, you can get adjacent plaintext bytes, eventually building the request that is being made.

Once the byte where credentials start is known, it can be automated to get the credentials and end when a `\r\n` is found.
