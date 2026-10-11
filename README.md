relmeauth-clj
=============

[![Clojars Project](https://img.shields.io/clojars/v/dk.simongray/relmeauth-clj.svg)](https://clojars.org/dk.simongray/relmeauth-clj)

This is a Clojure and ClojureScript implementation of
[RelMeAuth](https://indieweb.org/RelMeAuth), with which people sign in as
their own website through an account they have elsewhere. The site links
to the account with rel=me, the user signs in there with OAuth, and the
account links back to the site. It covers GitHub, Mastodon and the
servers that share Mastodon's API.

- **Both directions.** The account that signs in must be the one that
  the site names, and it must link back to the site: in GitHub's website
  field, or in a Mastodon bio or profile field.
- **Plain data.** Accounts, requests and sessions are maps, so the page
  where the user chooses an account is yours to render.
- **Nothing in the background.** Your app registers at a Mastodon server
  the first time a user signs in there, and the registration goes to a
  store of yours.
- **Safe by default.** Only the public internet is fetched, with limits,
  every sign-in uses PKCE, the state is tied to the browser, and client
  secrets are hidden texts that don't print.

The same code runs on the JVM and in Node. It needs the client secrets of
your app, so it runs on a server.

> This library was spun out of [indieblog](https://github.com/simongray/indieblog),
> the software of [simon.grays.blog](https://simon.grays.blog), whose
> owner signs in to its own IndieAuth server this way, and whose readers
> sign in to comment. Like indieblog, it was developed with assistance
> from frontier LLMs.

Getting started
---------------

It requires Clojure 1.11+ and Java 11+. For the latest release, add it
from [Clojars](https://clojars.org/dk.simongray/relmeauth-clj) to the
`:deps` in your `deps.edn`:

```clojure
dk.simongray/relmeauth-clj {:mvn/version "0.1.0"}
```

For changes that aren't released yet, use the SHA of the latest commit on
`master` instead:

```clojure
dk.simongray/relmeauth-clj
{:git/url "https://github.com/simongray/relmeauth-clj"
 :git/sha "…"}
```

For ClojureScript, shadow-cljs only reads Git dependencies from
`deps.edn`, so also set `:deps true` in your `shadow-cljs.edn`. A function
that fetches gives a promise there.

### Set up the providers

For GitHub, register an [OAuth app](https://github.com/settings/developers)
with your redirect URL as its callback URL. For Mastodon, there's nothing
to register by hand, but you need a store for the registrations. Then
give both to the library, along with the redirect URL:

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

The library only offers the providers that you set up. A store is a map
of two functions, so one for a file or a database takes a few lines, and
`relmeauth/memory-store` describes them. A registration lasts, so keep it
where a restart doesn't lose it.

### Sign a user in

Find the accounts that the user's site names with `discover!`:

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

The accounts come in the order of the rel=me links on the page. When
there's more than one, let the user choose. Then send the user's browser
to the provider with the URL of `authorization-request!`, and keep the
session it gives you where the browser's next request finds it, e.g. in
your session store:

```clojure
(def request
  (relmeauth/authorization-request! discovery
                                    (first (:accounts discovery))
                                    opts))
;; => {:url     "https://github.com/login/oauth/authorize?response_type=code&client_id=…"
;;     :session {:me "https://simon.grays.blog/" :state "…" :code-verifier "…" …}}
```

At a Mastodon server, it registers your app first if the store has no
registration for it. The browser comes back to the redirect URL with the
query parameters that `redeem!` takes, along with the session:

```clojure
(relmeauth/redeem! (:session request) query-params opts)
;; => {:me      "https://simon.grays.blog/"
;;     :account {:provider :github
;;               :username "simongray"
;;               :url      "https://github.com/simongray"}}
```

It checks the state, redeems the code, reads the account that signed in,
and checks that it's the account the site names and that it links back
to the site. A failure at any step gives a map of the `:error`, with its
`:type` and `:reason`, e.g. `::relmeauth/no-link-back`. The access token
isn't kept. Use the session once.

Anyone who can put a rel=me link on the user's page can sign in as the
user. So if the page shows what others write, e.g. comments, take rel=me
out of their links.

### Keep nothing on the server

If you'd rather not keep the session, add a `:secret` to the options, a
text of 32 bytes or more. The state then carries the session, signed,
and the session's `:nonce` goes in a cookie, e.g. `HttpOnly` and
`SameSite=Lax`. At the redirect URL, `state-session` gets the session
back from the state and the cookie's nonce, so that only the browser that
started a sign-in can finish it:

```clojure
(relmeauth/state-session secret (get query-params "state") nonce)
```

The session also carries the `:data` of the options, any EDN of yours,
e.g. the page to go back to.

### Sign in the owner of an IndieAuth server

A server of [indieauth-clj](https://github.com/simongray/indieauth-clj)
leaves signing in its user to an `:authorize` function of yours. With
this library, the owner signs in through their accounts rather than with
a password, and the request of the IndieAuth client goes along as data:

```clojure
(require '[dk.simongray.indieauth.server :as server]
         '[dk.simongray.wary-fetch.async :as async])

(defn authorize
  "Send the browser of the `ring-request` to the owner's first account,
  with the IndieAuth `request` in the state."
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
                   "Set-Cookie" (str "nonce=" (:nonce session)
                                     "; Path=/; HttpOnly; Secure; SameSite=Lax")}})))))
```

At the redirect URL, once `redeem!` gives the owner's URL, show the
consent page of the request that comes back:

```clojure
(server/consent (server/token-request (:data session) server-opts)
                (:me signed-in)
                server-opts)
```

Principles
----------

- **RelMeAuth first.** The code follows RelMeAuth and the algorithm on
  the microformats wiki, and cites the RFCs of OAuth for the rest.
- **Plain data.** Accounts, sessions and errors are maps, and every
  function that sends takes a `:send` of your own.
- **One codebase.** The library is written in `.cljc` and depends on
  [wary-fetch](https://github.com/simongray/wary-fetch) for requests,
  [html-pieces](https://github.com/simongray/html-pieces) for pages and
  [microformats-clj](https://github.com/simongray/microformats-clj) for
  their rel=me links.

Development
-----------

```bash
clojure -X:test                       # the tests on the JVM
npm install                           # once, for the Node tests
clojure -M:cljs compile test          # the tests in Node
clojure -M:cljs compile browser-test  # for a browser, from target/browser-test
```

The tests reproduce GitHub and a Mastodon server with Ring handlers in
memory, and on the JVM, a test also signs a user in over HTTP on
localhost. [doc/real-providers.md](doc/real-providers.md) says how to
sign in at the real ones by hand.

License
-------

The relmeauth-clj project is licensed under the [MIT licence](LICENSE).
