relmeauth-clj
=============

[![Clojars Project](https://img.shields.io/clojars/v/dk.simongray/relmeauth-clj.svg)](https://clojars.org/dk.simongray/relmeauth-clj)

This is a Clojure and ClojureScript implementation of
[RelMeAuth](https://indieweb.org/RelMeAuth), which lets people sign in as
their own website through an account they already have elsewhere. The
site links to the account with [rel=me](https://indieweb.org/rel-me), the
user signs in to the account with [OAuth](https://oauth.net/2/), and the
account links back to the site. It works with GitHub,
[Mastodon](https://joinmastodon.org/) and other servers that offer
[Mastodon's API](https://docs.joinmastodon.org/client/intro/).

- **Both directions.** The account that signs in must be the one that
  the site names, and it must link back to the site, either in GitHub's
  website field or in a Mastodon bio or
  [profile field](https://docs.joinmastodon.org/user/profile/#fields).
- **Plain data.** Accounts, requests and sessions are maps, so you render
  the page where the user chooses an account.
- **Nothing in the background.** Your app is registered at a Mastodon
  server only when a user first signs in there, and the registration goes
  to a store that you provide.
- **Safe by default.** Requests only go to the public internet, with
  limits on time and size. Every sign-in uses
  [PKCE](https://oauth.net/2/pkce/) and a
  [state](https://auth0.com/docs/secure/attack-protection/state-parameters)
  that is tied to the browser, and client secrets don't show up when
  printed.

The same code runs on the JVM and in [Node.js](https://nodejs.org/). Since
it needs the
[client secrets](https://www.oauth.com/oauth2-servers/client-registration/client-id-secret/)
of your app, use it on a server rather than in a browser.

> This library was spun out of [indieblog](https://github.com/simongray/indieblog),
> the software behind [simon.grays.blog](https://simon.grays.blog). There,
> the owner signs in to the blog's own
> [IndieAuth](https://indieweb.org/IndieAuth) server this way, and readers
> sign in to comment. Like indieblog, it was developed with assistance
> from frontier LLMs.

Getting started
---------------

It requires Clojure 1.11+ and Java 11+. For the latest release, add it
from [Clojars](https://clojars.org/dk.simongray/relmeauth-clj) to the
`:deps` in your `deps.edn`:

```clojure
dk.simongray/relmeauth-clj {:mvn/version "0.2.0"}
```

For changes that aren't released yet, use the SHA of the latest commit on
`master` instead:

```clojure
dk.simongray/relmeauth-clj
{:git/url "https://github.com/simongray/relmeauth-clj"
 :git/sha "…"}
```

For ClojureScript, shadow-cljs only reads Git dependencies from
`deps.edn`, so also set `:deps true` in your `shadow-cljs.edn`. The
functions that fetch return promises in ClojureScript.

### Set up the providers

For GitHub,
[register an OAuth app](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app)
with your [redirect URL](https://www.oauth.com/oauth2-servers/redirect-uris/)
as its callback URL. For Mastodon, there's nothing to register by hand,
since each server gets a
[registration](https://docs.joinmastodon.org/methods/apps/) of your app
when a user first signs in there, but you need a store for the
registrations. Put the GitHub app's client ID and secret, the store and
the redirect URL in the options:

```clojure
(require '[dk.simongray.relmeauth :as relmeauth]
         '[dk.simongray.wary-fetch.secret :as secret])

(def opts
  {:redirect-uri "https://simon.grays.blog/sign-in/callback"
   :github       {:client-id     "Ov23liAbCdEfGhIjKlMn"
                  :client-secret (secret/hide (System/getenv "GITHUB_SECRET"))}
   :mastodon     {:registrations (relmeauth/memory-store)
                  :client-name   "simon.grays.blog"}})
```

Only accounts at the providers in the options are offered. A store is a
map of two functions, so one for a file or a database takes a few lines,
and the docstring of `relmeauth/memory-store` describes them. Keep the
registrations where a restart doesn't lose them, or each restart leads to
new registrations at every server.

### Sign a user in

Use `discover!` to find the accounts that the user's site links to with
rel=me:

```clojure
(def discovery
  (relmeauth/discover! "simon.grays.blog" opts))
;; => {:me       "https://simon.grays.blog/"
;;     :urls     ["https://simon.grays.blog/"]
;;     :accounts [{:provider :github
;;                 :username "simongray"
;;                 :url      "https://github.com/simongray"}
;;                {:provider :mastodon
;;                 :instance "https://indieweb.social"
;;                 :username "simongray"
;;                 :url      "https://indieweb.social/@simongray"}]}
```

If you've fetched the page already, e.g. to find its IndieAuth server,
give the response to `discovery` for the same map. The accounts come in
the order of the site's rel=me links. When there's more than one, let the
user choose. Then send the user's browser to the
provider at the URL of `authorization-request!`, and keep the session
that it returns until the browser comes back, e.g. in your session store:

```clojure
(def request
  (relmeauth/authorization-request! discovery
                                    (first (:accounts discovery))
                                    opts))
;; => {:url     "https://github.com/login/oauth/authorize?response_type=code&client_id=…"
;;     :session {:me "https://simon.grays.blog/" :state "…" :code-verifier "…" …}}
```

For an account on a Mastodon server, `authorization-request!` also
registers your app there if the store has no registration yet. When the
browser comes back to the redirect URL, give `redeem!` the query
parameters and the session:

```clojure
(relmeauth/redeem! (:session request) query-params opts)
;; => {:me      "https://simon.grays.blog/"
;;     :account {:provider :github
;;               :username "simongray"
;;               :url      "https://github.com/simongray"}}
```

It checks the state, redeems the code for an
[access token](https://oauth.net/2/access-tokens/), and uses the token to
read the account that signed in. That must be the account that the site
names, and it must link back to the site. The token isn't kept. A
failure at any step gives a map of the `:error`, with its `:type` and
`:reason`, e.g. `::relmeauth/no-link-back`. Use each session only once.

Anyone who can put a rel=me link on the user's page can sign in as the
user. So if the page shows what others write, e.g. comments, remove
rel=me from their links, as html-pieces does when it sanitizes.

### Keep nothing on the server

To keep no session on the server, add a `:secret` to the options, a
string of 32 bytes or more, e.g. from indieauth-clj's `indieauth/token`.
The session's `:cookie` then carries the session, signed, so put it in a
[cookie](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Cookies),
e.g. one marked `HttpOnly` and `SameSite=Lax`. At the redirect URL,
`state-session` gets the session back from that cookie and the state, so
only the browser that started a sign-in can finish it:

```clojure
(relmeauth/state-session secret (get query-params "state") cookie)
```

Any EDN that you give as `:data` in the options comes back in the
session, e.g. the page to return to. The state stays short whatever the
session holds, since providers limit and log URLs, but a session too
large for a cookie throws rather than being dropped by the browser.

### Sign in the owner of an IndieAuth server

An IndieAuth server made with
[indieauth-clj](https://github.com/simongray/indieauth-clj) calls an
`:authorize` function of yours to sign in its user. With this library,
the site's owner can sign in through their accounts instead of with a
password, and the request of the IndieAuth client travels along as
`:data`:

```clojure
(require '[dk.simongray.indieauth.server :as server]
         '[dk.simongray.wary-fetch.async :as async])

(defn authorize
  "Send the browser of the `ring-request` to the owner's first account,
  with the IndieAuth `request` in the session's cookie."
  [ring-request request]
  (async/then
   (relmeauth/discover! "https://simon.grays.blog/" opts)
   (fn [{:keys [accounts] :as discovery}]
     (async/then
      (relmeauth/authorization-request! discovery (first accounts)
                                        (assoc opts :data (server/request-token request server-opts)))
      (fn [{:keys [url session]}]
        {:status  302
         :headers {"Location"   url
                   "Set-Cookie" (str "signin=" (:cookie session)
                                     "; Path=/; HttpOnly; Secure; SameSite=Lax")}})))))
```

At the redirect URL, once `redeem!` returns the owner's URL as the `:me`,
show the consent page for the request in the session's `:data`:

```clojure
(server/consent (server/token-request (:data session) server-opts)
                (:me signed-in)
                server-opts)
```

Principles
----------

- **RelMeAuth first.** The code follows RelMeAuth and its
  [algorithm on the microformats wiki](https://microformats.org/wiki/relmeauth),
  and cites the [RFCs of OAuth](https://oauth.net/specs/) for the rest.
- **Plain data.** Accounts, sessions and errors are maps, and every
  function that sends takes a `:send` of your own.
- **One codebase.** The library is written in `.cljc` and depends on
  [wary-fetch](https://github.com/simongray/wary-fetch) for requests,
  [html-pieces](https://github.com/simongray/html-pieces) for pages,
  [microformats-clj](https://github.com/simongray/microformats-clj) for
  their rel=me links and
  [indieauth-clj](https://github.com/simongray/indieauth-clj) for the
  URLs that a user can sign in as.

Development
-----------

```bash
clojure -X:test                       # the tests on the JVM
npm install                           # once, for the Node tests
clojure -M:cljs compile test          # the tests in Node
clojure -M:cljs compile browser-test  # for a browser, from target/browser-test
```

The tests reproduce GitHub and a Mastodon server with Ring handlers in
memory, and on the JVM, one test also signs a user in over HTTP on
localhost. To sign in at the real providers by hand, follow
[doc/real-providers.md](doc/real-providers.md).

License
-------

The relmeauth-clj project is licensed under the [MIT licence](LICENSE).
