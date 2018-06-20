# BigIP Cookie Scanner for Burp
Burp Extension for automatically finding and decoding insecure BigIP cookies

## Features
 * Passively scan sites for insecure BigIP-style cookies
 * Automatically decode the cookie

## Limitations
 * Only searches in the response, so clear cookies before use if you've visited the site before.

## Usage
 1. Download bigip.jar and load it into Burp Suite using the Extender.
 2. Visit a website with an insecure BigIP cookie.
 3. See the issue in the Issues pane with the decoded value.
