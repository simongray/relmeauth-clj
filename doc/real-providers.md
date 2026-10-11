Signing in at the real providers
================================

The tests reproduce GitHub and a Mastodon server in memory, so they
can't tell when a provider changes its API. To check against the real
ones, sign in by hand from a REPL. Nothing needs to answer at the
redirect URL: the browser shows an error there, and you copy the URL of
the page it couldn't open.

Before you start
----------------

- A site of your own on the public internet whose page links to your
  accounts with rel=me, e.g. `<a rel="me" href="https://github.com/you">`.
- On GitHub, your site in the website field of your profile.
- On Mastodon, your site in your bio or a profile field.
- A GitHub OAuth app, at https://github.com/settings/developers, with
  `http://127.0.0.1/callback` as its callback URL.

Sign in
-------

Start a REPL with `clojure -M:nrepl`, and set up both providers:

```clojure
(require '[clojure.string :as str]
         '[dk.simongray.relmeauth :as relmeauth]
         '[dk.simongray.wary-fetch.secret :as secret]
         '[dk.simongray.wary-fetch.url :as url])

(def opts
  {:redirect-uri "http://127.0.0.1:8123/callback"
   :github       {:client-id     "your client ID"
                  :client-secret (secret/hide "your client secret")}
   :mastodon     {:registrations (relmeauth/memory-store)
                  :client-name   "relmeauth-clj by hand"}})

(def discovery
  (relmeauth/discover! "your.site" opts))
```

GitHub takes another port of a loopback address than its callback URL's,
so any free port does. Check that `:accounts` lists your accounts. Then
sign in with one of them:

```clojure
(def request
  (relmeauth/authorization-request! discovery (first (:accounts discovery)) opts))

(:url request)
```

Open the URL in a browser, sign in and approve. When the browser fails to
open `http://127.0.0.1:8123/callback?code=…`, copy that URL and redeem
the code before it expires, within 10 minutes at GitHub:

```clojure
(def callback "http://127.0.0.1:8123/callback?code=…&state=…")

(relmeauth/redeem! (:session request)
                   (url/query-params (second (str/split callback #"\?" 2)))
                   opts)
;; => {:me "https://your.site/" :account {…}}
```

Do the same with your Mastodon account, giving `authorization-request!`
its entry in the `:accounts`. The first request registers an app at your
server, whose page of approval then shows the client name.

What to check
-------------

- Both accounts sign in and give your site's URL as the `:me`.
- With a fresh request, take the link to your site out of the profile
  first, and `redeem!` gives the `:type` `::relmeauth/no-link-back`.
- With a fresh request, say no at the provider, and `redeem!` gives the
  `::relmeauth/authorization-error` with the `:code` `access_denied`.
- A code redeemed a second time gives the `::relmeauth/token-error`.
- On Mastodon 4.3 or later, the page of approval asks for your profile
  alone, and on an older server for read access to your account.

Afterwards, revoke the app at GitHub under Settings → Applications, and
at your Mastodon server under Preferences → Account → Authorized apps.
