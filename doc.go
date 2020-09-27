// Copyright 2020 The Go-Guardian. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

/*Package guardian .
Go-Guardian is a golang library that provides a simple, clean, and idiomatic way to create powerful modern API and web authentication.

Go-Guardian sole purpose is to authenticate requests, which it does through an extensible set of authentication methods known as strategies.
Go-Guardian does not mount routes or assume any particular database schema, which maximizes flexibility and allows decisions to be made by the developer.
The API is simple: you provide go-guardian a request to authenticate, and go-guardian invoke strategies to authenticate end-user request.
Strategies provide callbacks for controlling what occurs when authentication `should` succeeds or fails.

Why Go-Guardian?

When building a modern application, you don't want to implement authentication module from scratch;
you want to focus on building awesome software. go-guardian is here to help with that.

Here are a few bullet point reasons you might like to try it out:
	* provides simple, clean, and idiomatic API.
	* provides top trends and traditional authentication methods.
	* provides a package to caches the authentication decisions, based on different mechanisms and algorithms.
	* provides two-factor authentication and one-time password as defined in [RFC-4226](https://tools.ietf.org/html/rfc4226) and [RFC-6238](https://tools.ietf.org/html/rfc6238)
	* provides a mechanism to customize strategies, even enables writing a custom strategy
*/
//nolint:lll
package guardian
