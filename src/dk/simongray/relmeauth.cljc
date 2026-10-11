(ns dk.simongray.relmeauth
  "RelMeAuth: signing a user in as their website, with an account at GitHub
  or on a Mastodon server that the site names with rel=me.

  The user signs in at the account with OAuth, and the sign-in counts when
  it's the account that the site names, and when the account links back to
  the site: in GitHub's website field, or in a Mastodon bio or profile
  field. The code follows https://indieweb.org/RelMeAuth and the algorithm
  at https://microformats.org/wiki/relmeauth."
  (:require [clojure.string :as str]
            [dk.simongray.html-pieces :as html]
            [dk.simongray.microformats :as mf]
            [dk.simongray.relmeauth.bytes :as bytes]
            [dk.simongray.relmeauth.providers :as providers]
            [dk.simongray.relmeauth.requests :as requests]
            [dk.simongray.relmeauth.signed :as signed]
            [dk.simongray.relmeauth.url :as url]
            [dk.simongray.wary-fetch :as http]
            [dk.simongray.wary-fetch.async :as async]
            [dk.simongray.wary-fetch.headers :as headers]))

;;; options

(def default-options
  "The default of each option that has one:

  - :profile-url-pred, url/profile-url?, the URLs that a user can sign in as,
    those that IndieAuth takes
  - :silo-urls?, false: a user can't sign in as an account at a provider,
    e.g. https://github.com/ann, since the URL isn't the user's own, as
    the algorithm on the microformats wiki has it. The provider can give
    the username to someone else.
  - :trim-slash?, true: a slash at the end of a path doesn't count when an
    account's links are compared with the user's URLs, so that a link to
    https://example.com/me links back to https://example.com/me/. The :me
    keeps its slash.
  - :session-seconds, 600: how long a user has to sign in at the provider,
    and how long a signed state lasts
  - :timeout-seconds, 10: the limit of each request
  - :max-redirects, 5: how many redirects the fetch of the user's page
    follows
  - :max-page-bytes, 2 MB: the largest page of a user
  - :max-json-bytes, 256 kB: the largest JSON document of a provider
  - :send, http/send-public!, which sends to the public internet alone
  - :now-fn, a function that gives the instant now"
  {:profile-url-pred url/profile-url?
   :silo-urls?       false
   :trim-slash?      true
   :session-seconds  600
   :timeout-seconds  10
   :max-redirects    5
   :max-page-bytes   (* 2 1024 1024)
   :max-json-bytes   (* 256 1024)
   :send             http/send-public!
   :now-fn           #?(:clj  #(java.util.Date.)
                        :cljs #(js/Date.))})

(defn token
  "A random text of `n` bytes, 32 by default, that nobody can guess, e.g.
  for a state or a secret. The bytes come from a secure source, and the
  text is in the URL-safe letters of base64."
  ([]
   (token 32))
  ([n]
   (bytes/base64url (bytes/random n))))

(defn memory-store
  "A store of registrations in the atom `a`, or in a new one, as a map of
  each instance to its registration.

  A store is a map of functions, which can give their results as promises
  in ClojureScript:

  - :get, a function of an instance that gives its registration, or nil
  - :put!, a function of an instance and its registration that keeps it

  A registration is a map of the :client-id, the :client-secret, the
  :scope and the :redirect-uri, and it can have :expires, the instant when
  the server stops taking it. The client secret is a hidden text of
  wary-fetch, so a store that writes EDN reveals it with secret/reveal."
  ([]
   (memory-store (atom {})))
  ([a]
   {:get  #(get @a %)
    :put! #(swap! a assoc %1 %2)}))

;;; discovery

(defn- page-nodes
  "The Hiccup of the HTML page in the `response`, or nil when it holds
  another kind of document."
  [{:keys [headers body] :as response}]
  (let [type (headers/media-type (headers/header headers "content-type"))]
    (when (and (string? body)
               (contains? #{nil "text/html" "application/xhtml+xml"} type))
      (html/parse body))))

;; RelMeAuth: the rel=me links of the page, in their order. Unlike the
;; links of IndieAuth, those of a and link elements anywhere count.
(defn accounts
  "The accounts that the rel=me links of the page in the `response` name,
  at the providers that `opts` set up: GitHub with :github and Mastodon
  servers with :mastodon. They come in the order of the page, once each.

  A relative link counts from the URL of the response, or from the base
  of the page."
  [response opts]
  (->> (get-in (mf/parse (page-nodes response) (:url response)) [:rels "me"])
       (keep providers/account)
       (filter #(contains? opts (:provider %)))
       distinct
       vec))

(defn discover!
  "Fetch the page of the profile URL `url` with `opts`, and give the
  accounts that the user can sign in with, as a map:

  - :me, the URL in canonical form
  - :urls, the URLs that discovery went through: :me, those that
    redirected, and the last, in canonical form
  - :accounts, those of the accounts function

  A failure gives a map of the :error, with its :type and :reason. The
  `opts` are those of default-options and authorization-request!. In
  ClojureScript, it gives a promise."
  [url opts]
  (let [{:keys [profile-url-pred silo-urls? max-page-bytes]
         :as   opts} (merge default-options opts)
        me           (url/canonical-url url)
        problem      (cond
                       (not (and me (profile-url-pred me)))
                       (requests/failure ::invalid-url
                                         (str "Not a profile URL: " url)
                                         {:url url})

                       (and (not silo-urls?) (providers/account me))
                       (requests/failure ::silo-url
                                         (str "An account at a provider, not"
                                              " a site of the user's own: " url)
                                         {:url url}))]
    (if problem
      (async/then nil (constantly problem))
      (requests/and-then
       (requests/fetch! me "text/html, application/xhtml+xml;q=0.9, */*;q=0.1"
                        max-page-bytes opts)
       (fn [{:keys [redirects] :as response}]
         {:me       me
          :urls     (->> (concat [me] (map second redirects) [(:url response)])
                         (keep url/canonical-url)
                         distinct
                         vec)
          :accounts (accounts response opts)})))))

;;; signing in

(def ^:no-doc session-kind
  "The kind of a signed state that carries a session."
  ::session)

(defn- fingerprint
  "The SHA-256 of the text `s` in the URL-safe letters of base64."
  [s]
  (bytes/base64url (bytes/sha256 (bytes/encode s))))

;; RFC 6749, section 4.1.1; RFC 7636, section 4.3
(defn authorization-request!
  "Give the URL at the provider of the `account` to send the user's browser
  to, and the session to keep until the browser comes back, as a map of
  :url and :session, for the `discovery` of discover!, by `opts`:

  - :redirect-uri, the URL that the browser comes back to, which your
    GitHub OAuth app lists
  - :github, the :client-id and :client-secret of your GitHub OAuth app,
    the secret as a hidden text of wary-fetch
  - :mastodon, a map of the :registrations store, e.g. memory-store, and
    the :client-name to show the user, the domain of the redirect URL by
    default, and the :website of your app
  - :secret, a text of 32 bytes or more, e.g. a token, to sign the session
    into the state, so that state-session gets it back from the state
  - :data, any EDN that the session carries for you, e.g. the request of
    an IndieAuth server that the user signs in for
  - :now-fn, as default-options has it

  Keep the session where the browser's next request finds it, e.g. in a
  session store, since it holds the PKCE code verifier and the state that
  ties the answer to this browser. With a :secret, keep its :nonce in a
  cookie instead, and give it to state-session with the state. At a
  Mastodon server, it registers your app first, if the store has no
  registration, and a server that refuses gives a map of the :error. In
  ClojureScript, it gives a promise."
  [{:keys [me urls] :as discovery} account opts]
  (let [{:keys [redirect-uri secret data now-fn] :as opts} (merge default-options
                                                                  opts)]
    (when-let [problem (providers/request-problem account opts)]
      (throw (ex-info problem {:account account :redirect-uri redirect-uri})))
    (requests/and-then
     (providers/client! account opts)
     (fn [{:keys [client-id scope]}]
       (let [session  (cond-> {:me           me
                               :urls         urls
                               :account      account
                               :redirect-uri redirect-uri}
                        scope        (assoc :scope scope)
                        (some? data) (assoc :data data))
             nonce    (when secret (token))
             state    (if secret
                        (signed/sign secret session-kind
                                     (assoc session :nonce (fingerprint nonce))
                                     (now-fn))
                        (token))
             verifier (if secret
                        (signed/derive-text secret "code_verifier" state)
                        (token))
             session  (cond-> (assoc session :state state :code-verifier verifier)
                        nonce (assoc :nonce nonce))]
         {:url     (providers/authorization-url session client-id)
          :session session})))))

;; RFC 9700, section 4.7.1: a state that is bound to the browser
(defn state-session
  "The session that the signed `state` carries, which authorization-request!
  gave with the `secret`, if the `nonce` is the session's, or nil. It's nil
  too when the state is older than the :session-seconds of `opts`.

  The nonce comes from the browser that came back, e.g. from a cookie,
  so that only the browser that started the sign-in can finish it."
  ([secret state nonce]
   (state-session secret state nonce {}))
  ([secret state nonce opts]
   (let [{:keys [session-seconds now-fn]} (merge default-options opts)
         m (signed/unsign secret session-kind state (now-fn) session-seconds)]
     (when (and m
                (string? nonce)
                (bytes/same? (bytes/encode (fingerprint nonce))
                             (bytes/encode (str (:nonce m)))))
       (assoc m
              :nonce         nonce
              :state         state
              :code-verifier (signed/derive-text secret "code_verifier" state))))))

;;; the callback

(defn- param
  "The value of the parameter `k` in `params`, a map whose keys are texts
  or keywords, and the first when it has several."
  [params k]
  (let [v (get params k (get params (keyword k)))]
    (if (sequential? v) (first v) v)))

;; RFC 6749, section 4.1.2
(defn callback-problem
  "What's wrong with the query `params` that the browser came back with,
  for the `session`, as a map of the :type and the :reason, or nil.

  The params are a map by name, with texts or keywords as keys. The state
  must be the session's. An answer of the provider with an error, e.g.
  access_denied when the user said no, is a problem of the type
  ::authorization-error, with the :code that the provider gave."
  [{:keys [state] :as session} params]
  (let [given (param params "state")
        error (param params "error")]
    (cond
      (not (and (string? given)
                (string? state)
                (bytes/same? (bytes/encode given) (bytes/encode state))))
      {:type ::state-mismatch :reason "The state isn't the one that was sent"}

      error
      {:type   ::authorization-error
       :code   error
       :reason (or (param params "error_description")
                   (str "The provider answered " error))}

      (empty? (param params "code"))
      {:type ::no-code :reason "The provider gave no code"})))

;; RelMeAuth: the account that signed in is the one that the page names,
;; and it links back to the page
(defn account-problem
  "What's wrong with the `info` of the account that signed in, for the
  `session`, by the :trim-slash? of `opts`, as a map of the :type and the
  :reason, or nil.

  The info is the JSON of the provider's API, as a map. The account must
  be the one of the session, by its username in any case, and one of its
  account-links must be one of the :urls of the session, in canonical
  form."
  ([session info]
   (account-problem session info {}))
  ([{:keys [me urls account] :as session} info opts]
   (let [{:keys [trim-slash?]}       (merge default-options opts)
         {:keys [provider username]} account
         signed-in                   (providers/username provider info)
         same                        (if trim-slash? url/trim-slash identity)
         links                       (keep #(some-> (url/canonical-url %) same)
                                           (providers/links provider info))]
     (cond
       (not (and (string? signed-in)
                 (= (str/lower-case username) (str/lower-case signed-in))))
       {:type   ::wrong-account
        :reason (str "The user signed in as " (pr-str signed-in) ", not as "
                     username)}

       (not-any? (set (map same urls)) links)
       {:type   ::no-link-back
        :reason (str (:url account) " doesn't link back to " me)}))))

(defn redeem!
  "Finish signing in when the user's browser comes back with the query
  `params`, for the `session` that authorization-request! gave, with
  `opts`, and give a map of the :me and the :account that the user signed
  in with. In ClojureScript, it gives a promise.

  It checks the params with callback-problem, redeems the code for an
  access token, reads the account with it, and checks the account with
  account-problem. A failure at any of them gives a map of the :error,
  with its :type and its :reason. The access token isn't kept. The `opts`
  are those of authorization-request!."
  [{:keys [me account] :as session} params opts]
  (let [opts (merge default-options opts)]
    (if-let [problem (callback-problem session params)]
      (async/then nil (constantly {:error problem}))
      (-> (providers/redeeming-client! session opts)
          (requests/and-then #(providers/access-token! session % (param params "code") opts))
          (requests/and-then #(providers/account-info! session (:access-token %) opts))
          (requests/and-then (fn [info]
                               (if-let [problem (account-problem session info opts)]
                                 {:error problem}
                                 {:me me :account account})))))))
