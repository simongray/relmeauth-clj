(ns dk.simongray.relmeauth
  "RelMeAuth: signing a user in as their website, with an account at GitHub
  or on a Mastodon server that the site names with rel=me.

  A sign-in counts when the account that signed in is the one that the
  site names, and when it links back to the site. The code follows
  https://indieweb.org/RelMeAuth and the algorithm at
  https://microformats.org/wiki/relmeauth. The URLs that a user can sign
  in as, and their canonical form, are those of IndieAuth, from
  indieauth-clj."
  (:require [clojure.string :as str]
            [dk.simongray.html-pieces :as html]
            [dk.simongray.indieauth :as indieauth]
            [dk.simongray.indieauth.bytes :as bytes]
            [dk.simongray.indieauth.state :as state]
            [dk.simongray.microformats :as mf]
            [dk.simongray.relmeauth.providers :as providers]
            [dk.simongray.relmeauth.requests :as requests]
            [dk.simongray.wary-fetch :as http]
            [dk.simongray.wary-fetch.async :as async]
            [dk.simongray.wary-fetch.headers :as headers]))

;;; options

(def default-options
  "The default of each option that has one:

  - :profile-url-pred, indieauth/profile-url?, the URLs that a user can
    sign in as, those that IndieAuth takes
  - :silo-urls?, false: refuse a URL that is an account at a provider,
    e.g. https://github.com/ann, since it isn't the user's own
  - :trim-slash?, true: let a link back differ from the user's URL by a
    slash at the end of its path
  - :session-seconds, 600: how long a user has to sign in at the provider,
    and how long a signed state lasts
  - :timeout-seconds, 10: the limit of each request
  - :max-redirects, 5: how many redirects the fetch of the user's page
    follows
  - :max-page-bytes, 2 MB: the largest page of a user
  - :max-json-bytes, 256 kB: the largest JSON document of a provider
  - :send, http/send-public!, which sends to the public internet alone
  - :now-fn, a function that gives the instant now"
  {:profile-url-pred indieauth/profile-url?
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

(defn memory-store
  "A store of registrations in the atom `a`, or in a new one, as a map of
  the :instance of each Mastodon server to your app's registration there.

  A store is a map of :get, a function of an instance that gives its
  registration or nil, and :put!, a function of an instance and a
  registration that keeps it. Either can give a promise in ClojureScript.
  A registration is a map of the :client-id, :client-secret, :scope,
  :redirect-uri and, if it expires, :expires. Its client secret is a hidden
  text of wary-fetch, so reveal it to write it as EDN."
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
  servers with :mastodon. They come in the order of the page, once each."
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
        me           (indieauth/canonical-url url)
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
                         (keep indieauth/canonical-url)
                         distinct
                         vec)
          :accounts (accounts response opts)})))))

;;; signing in

(def ^:no-doc session-kind
  "The kind of a signed state that carries a session."
  ::session)

;; RFC 6749, section 4.1.1; RFC 7636, section 4.3
(defn authorization-request!
  "Give the URL at the provider of the `account` to send the user's browser
  to, and the session to keep until the browser comes back, as a map of
  :url and :session, for the `discovery` of discover!, by `opts`:

  - :redirect-uri, the URL that the browser comes back to
  - :github, the :client-id and :client-secret of your GitHub OAuth app,
    the secret as a hidden text of wary-fetch
  - :mastodon, the :registrations store, e.g. memory-store, and the
    :client-name and :website that a server shows of your app
  - :secret, a text of 32 bytes or more, to carry the session in the
    state, signed, for state-session
  - :data, any EDN of yours that the session carries

  Keep the session for the browser's next request, or with a :secret, its
  :nonce in a cookie. A Mastodon server that refuses to register your app
  gives a map of the :error. In ClojureScript, it gives a promise."
  [{:keys [me urls] :as discovery} account opts]
  (let [{:keys [redirect-uri secret data now-fn] :as opts} (merge default-options
                                                                  opts)]
    (when-let [problem (providers/request-problem account opts)]
      (throw (ex-info problem {:account account :redirect-uri redirect-uri})))
    (requests/and-then
     (providers/client! account opts)
     (fn [{:keys [client-id scope]}]
       (let [session (cond-> {:me           me
                              :urls         urls
                              :account      account
                              :redirect-uri redirect-uri}
                       scope        (assoc :scope scope)
                       (some? data) (assoc :data data))
             session (merge session
                            (state/fresh secret session-kind session (now-fn)))]
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
   (let [{:keys [session-seconds now-fn]} (merge default-options opts)]
     (state/session secret session-kind state nonce (now-fn) session-seconds))))

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

  The state must be the session's. An error of the provider, e.g.
  access_denied when the user said no, is an ::authorization-error with
  the provider's :code."
  [{:keys [state] :as session} params]
  (let [given (param params "state")
        error (param params "error")]
    (cond
      (not (bytes/same-text? given state))
      {:type ::state-mismatch :reason "The state isn't the one that was sent"}

      error
      {:type   ::authorization-error
       :code   error
       :reason (or (param params "error_description")
                   (str "The provider answered " error))}

      (empty? (param params "code"))
      {:type ::no-code :reason "The provider gave no code"})))

(defn ^:no-doc trim-slash
  "The canonical `url` without a slash at the end of its path, unless the
  path is /.

      (trim-slash \"https://example.com/me/\") ;; => \"https://example.com/me\""
  [url]
  (str/replace url #"^(https?://[^/?#]*/[^?#]*[^/?#])/(?=[?#]|$)" "$1"))

;; RelMeAuth: the account that signed in is the one that the page names,
;; and it links back to the page
(defn account-problem
  "What's wrong with the `info` of the account that signed in, the JSON of
  the provider's API, for the `session` and by `opts`, as a map of the
  :type and the :reason, or nil.

  The account must be the session's, by its username in any case, and it
  must link back to one of the session's :urls."
  ([session info]
   (account-problem session info {}))
  ([{:keys [me urls account] :as session} info opts]
   (let [{:keys [trim-slash?]}       (merge default-options opts)
         {:keys [provider username]} account
         signed-in                   (providers/username provider info)
         same                        (if trim-slash? trim-slash identity)
         links                       (keep #(some-> (indieauth/canonical-url %) same)
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
  `params`, for the `session` of authorization-request!, by `opts`, and
  give a map of the :me and the :account that signed in. In
  ClojureScript, it gives a promise.

  The params must pass callback-problem, and the account account-problem.
  A failure gives a map of the :error. The :me keeps any slash at its end,
  and the access token isn't kept."
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
