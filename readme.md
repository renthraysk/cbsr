# CBSR

Serving immutable HTTP sub resources from embed.FS using cache busting urls.

## Encoding content negotation

If multiple encoded versions exist in the embeded file system, eg.

- ``js/default.js.gz``
- ``js/default.js.br``
- ``js/default.js``

this will perform negotiation per request, between the 3 encodings.

It is server driven content negotation. It ignores user agent q values, unless they are 0.
The encoding that has the smallest size that the user agent supports is what is sent.
If two encodings share the same size, then identity, gzip, brotli is this order of preference.

## Cache busting URLs

A hash is inserted into the base name (filename without any encoding filename extension).
	
So the 3 files in example above will be negotated between from a single ``http.Handler`` registered with ``http.ServeMux`` with a pattern of "``js/default.<hash>.js``".

The hash is derived by hashing over each variant response (http header & bodies) in ascending size. So any change in any response, or relative ordering should generate a new hash, and therefore cause user agents to fetch the most up to date version.

