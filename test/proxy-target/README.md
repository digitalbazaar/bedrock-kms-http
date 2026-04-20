# Bedrock KMS module proxy target

## What is it?

Bedrock KMS HTTP can be configured to proxy KMS requests to one or more other
systems (called "proxy targets") based on the KMS module identified in the
request.

A "proxy target" is another instance of Bedrock KMS HTTP that will actually
run the KMS operations and return their results. This allows the proxy target
to be run inside of an isolated environment with only the necessary code it
needs to run the KMS stack and whatever KMS modules are supported. This
isolated environment can even be run a secure enclave that supports general
applications (like node.js apps), adding an additional security layer. It
should also be configured to only receive traffic from the proxy, reducing
the attack surface.
