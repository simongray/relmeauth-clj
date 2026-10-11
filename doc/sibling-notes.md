Sibling notes
=============

What relmeauth-clj needed from indieauth-clj, wary-fetch, html-pieces and
microformats-clj, what it did instead, and what those libraries could
offer.

indieauth-clj
-------------

- **Canonical URLs.** Needed IndieAuth's canonical form of a URL and its
  rules for a profile URL, so that the URL a user signs in as compares
  the same way at an IndieAuth server of indieauth-clj. Did instead: a
  copy of `canonical-url`, `profile-url?`, `url-parts` and
  `authority-parts` in the root namespace. indieauth-clj isn't released,
  and a Git dependency would keep this library off Clojars. Could offer:
  once indieauth-clj is on Clojars, this library could depend on it for
  them, or `url-parts` could move to wary-fetch as the notes of
  indieauth-clj propose.
- **Signed states.** Needed a session signed into the state, with its
  nonce in a cookie, and the PKCE verifier derived from the state. Did
  instead: copies of `bytes.cljc` and `signed.cljc`, and a
  `state-session` with the same arguments as indieauth-clj's.
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

- **Hashes, randomness and JSON.** Needed the same as indieauth-clj: SHA-256,
  HMAC-SHA256, secure random bytes and base64url, and JSON of GitHub's
  and Mastodon's answers. Did instead: copies of indieauth-clj's
  `bytes.cljc` and `json.cljc`, with data.json on the JVM. This is the
  third library with them. Could offer: `wary-fetch.bytes` and `:as
  :json`, as indieauth-clj's notes say.
- **A form for an OAuth endpoint.** Needed a POST of a form whose body
  holds a secret, without following redirects, and the JSON object of the
  answer or the OAuth error in it (RFC 6749, section 5.2), which GitHub
  gives with 200. Did instead: `form-request`, `exchange!` and
  `json-answer`, close to indieauth-clj's own. Could offer: a
  `form-request` with a hidden body, since every OAuth client and
  Micropub posts forms.
- **A network of Ring handlers for tests.** Needed to send requests to
  Ring handlers in memory, with redirects and cookies, and to the same
  handlers over HTTP on localhost. Did instead: a copy of indieauth-clj's
  test support, whose server on localhost came from websub-clj's. Could
  offer: a `:send` of Ring handlers for tests, e.g. in a small library of
  its own.

html-pieces
-----------

- **rel=me in what others write.** RelMeAuth trusts every rel=me link on
  the user's page, so a comment with `<a rel="me" href=…>` lets its
  writer sign in as the owner, if the comment's account links back.
  `html/hiccup` and `html/sanitize` keep `rel` on `a`, me included. Did
  instead: the README tells you to take rel=me out of what others write.
  Could offer: leaving out the `me` of a `rel` by default, since it
  claims an identity, or an option for it. Mastodon's verification of
  profile links has the same weakness.
- **The links of a piece of HTML.** Needed the hrefs of the a elements in
  a Mastodon bio and in its profile fields. Did instead: a private
  `hrefs`, a tree-seq over `html/parse`. Could offer: `links` of parsed
  nodes, as indieauth-clj's notes propose for the head of a page.

microformats-clj
----------------

- **rel=me links.** `mf/parse` gives the `:rels` of a and link elements
  anywhere in the page, which is what RelMeAuth wants, unlike IndieAuth,
  so nothing is missing. It parses every microformat of the page too,
  only for the rels to be read. Could offer: `rels` of a page alone.
