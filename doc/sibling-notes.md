Sibling notes
=============

What relmeauth-clj needed from indieauth-clj, wary-fetch, html-pieces and
microformats-clj, what it did instead, and what those libraries could
offer.

indieauth-clj
-------------

- **Canonical URLs.** Needed IndieAuth's canonical form of a URL and its
  rules for a profile URL, so that the URL a user signs in as compares
  the same way at an IndieAuth server of indieauth-clj. Did: depend on
  indieauth-clj for `canonical-url` and `profile-url?`. Nothing is
  missing.
- **Signed states.** Needed a session signed into the state, with its
  nonce in a cookie, and the PKCE verifier derived from the state, of a
  kind of its own, since a state of RelMeAuth must never pass for one of
  IndieAuth under a shared secret. Did: use `dk.simongray.indieauth.state`,
  which takes the kind from its caller, and a `state-session` with the
  same arguments as indieauth-clj's. Nothing is missing.
- **The request of an IndieAuth server.** `request-token` and
  `token-request` were all it took to carry the request through a sign-in
  with RelMeAuth, as the `:data` of the state. Nothing is missing.

indieblog's canonical form trimmed a slash at the end of a path, so
`https://example.com/me/` and `https://example.com/me` were one URL. This
library keeps the `:me` in IndieAuth's form, where they're two, and
trims the slash only to compare an account's links, unless
`:trim-slash?` is false.

wary-fetch
----------

- **Hashes and JSON.** Needed a comparison in constant time and the JSON
  of GitHub's and Mastodon's answers on both platforms. Did: use
  `wary-fetch.bytes` and `wary-fetch.json` of 0.3.0. Nothing is missing.
- **A form for an OAuth endpoint.** Needed a POST of a form whose body
  holds a secret, and the JSON object of the answer or the OAuth error in
  it (RFC 6749, section 5.2), which GitHub gives with 200. Did: use
  `http/form-request`, and read the error with a `json-answer` of this
  library's own, since wary-fetch reads no OAuth errors.
- **A network of Ring handlers for tests.** Needed to send requests to
  Ring handlers in memory, with redirects and cookies, and to the same
  handlers over HTTP on localhost. Did instead: a copy of indieauth-clj's
  test support, whose server on localhost came from websub-clj's.
  wary-fetch won't offer it.

html-pieces
-----------

- **rel=me in what others write.** RelMeAuth trusts every rel=me link on
  the user's page, so a comment with `<a rel="me" href=…>` would let its
  writer sign in as the owner, if the comment's account links back.
  html-pieces 0.4.0 takes me out of a rel when it sanitizes, by default.
  Nothing is missing.
- **The links of a piece of HTML.** Needed the hrefs of the a elements in
  a Mastodon bio and in its profile fields. Did: use `html/links` of
  0.4.0. Nothing is missing.

microformats-clj
----------------

- **rel=me links.** Needed the rels of a and link elements anywhere in
  the page, which is what RelMeAuth wants, unlike IndieAuth. Did: use
  `mf/rels` of 0.2.0, which skips the microformats of the page. Nothing
  is missing.
