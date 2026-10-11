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
            [dk.simongray.relmeauth.json :as json]
            [dk.simongray.relmeauth.requests :as requests]
            [dk.simongray.relmeauth.signed :as signed]
            [dk.simongray.wary-fetch :as http]
            [dk.simongray.wary-fetch.async :as async]
            [dk.simongray.wary-fetch.headers :as headers]
            [dk.simongray.wary-fetch.secret :as secret]
            [dk.simongray.wary-fetch.url :as url]))

;;; URLs, as indieauth-clj has them (see doc/sibling-notes.md)

;; RFC 3986, appendix B
(defn ^:no-doc url-parts
  "The parts of the URL `s` as a map of :scheme, :authority, :path, :query
  and :fragment, each nil when the URL has none, or nil when `s` has no
  scheme. The scheme is in lower case."
  [s]
  (when-let [[_ scheme _ authority path _ query _ fragment]
             (re-matches #"(?s)([a-zA-Z][a-zA-Z0-9+.\-]*):(//([^/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?"
                         (str s))]
    {:scheme    (str/lower-case scheme)
     :authority authority
     :path      path
     :query     query
     :fragment  fragment}))

(defn ^:no-doc authority-parts
  "The user information, host and port of the `authority` of a URL, as a
  map of :userinfo, :host and :port, each nil when it has none."
  [authority]
  (let [at       (str/last-index-of authority "@")
        userinfo (when at (subs authority 0 at))
        hostport (if at (subs authority (inc at)) authority)
        [_ host port] (re-matches #"(\[[^\]]*\]|[^:]*)(?::(.*))?" hostport)]
    {:userinfo userinfo
     :host     host
     :port     port}))

(defn- domain-name?
  "Whether the `host` of a URL is a domain name: labels between dots, of
  characters that a host may have, and not an IP address, which a host
  that ends in a number is, as a browser reads it."
  [host]
  (let [h (str/replace (str/lower-case host) #"\.$" "")]
    (boolean (and (re-matches #"[^\x00-\x20\x7f#%/:<>?@\[\\\]^|]+" h)
                  (every? seq (str/split h #"\." -1))
                  (not (re-find #"(^|\.)(\d+|0x[0-9a-f]*)$" h))
                  (nil? (url/ip-address h))))))

(defn- dot-segment?
  "Whether the path `segment` is . or .., also when percent-encoded, as a
  browser reads it."
  [segment]
  (boolean (re-matches #"(?i)(\.|%2e){1,2}" segment)))

;; IndieAuth 3.2
(defn profile-url?
  "Whether `s` is a valid profile URL of a user, as IndieAuth has it: an
  http or https URL with a domain name, without a port, a fragment, a user
  name or a password, or a . or .. segment in its path.

      (profile-url? \"https://example.com/users?id=100\") ;; => true
      (profile-url? \"https://example.com:8443/\")        ;; => false"
  [s]
  (let [{:keys [scheme authority path fragment]} (url-parts s)
        {:keys [userinfo host port]}             (some-> authority
                                                         authority-parts)]
    (boolean (and (string? s)
                  (not (re-find #"[\x00-\x20\x7f\\]" s))
                  (#{"http" "https"} scheme)
                  (not-any? dot-segment? (str/split path #"/"))
                  (nil? fragment)
                  (nil? userinfo)
                  (nil? port)
                  (seq host)
                  (domain-name? host)))))

(def ^:no-doc default-ports
  "The port of each scheme of the web, which a canonical URL leaves out."
  {"http" "80" "https" "443"})

;; IndieAuth 3.4
(defn canonical-url
  "The URL that the text `s` names, in the canonical form that IndieAuth
  compares, or nil when it names no http or https URL.

  A host alone becomes an https URL, as people write it in a sign-in form
  or in a profile field. The scheme and the host are in lower case, a
  default port is left out, and an empty path is /. Nothing else changes.

      (canonical-url \"Example.com\") ;; => \"https://example.com/\""
  [s]
  (let [s    (str/trim (str s))
        s    (if (or (re-find #"(?i)^https?://" s)
                     (re-find #"^[a-zA-Z][a-zA-Z0-9+.\-]*:(?!\d)" s))
               s
               (str "https://" s))
        {:keys [scheme authority path query fragment]} (url-parts s)
        {:keys [userinfo host port]} (some-> authority authority-parts)]
    (when (and (#{"http" "https"} scheme) (seq host))
      (str scheme "://"
           (some-> userinfo (str "@"))
           (str/lower-case host)
           (when (and port (not= port (default-ports scheme)))
             (str ":" port))
           (if (empty? path) "/" path)
           (some->> query (str "?"))
           (some->> fragment (str "#"))))))

(defn token
  "A random text of `n` bytes, 32 by default, that nobody can guess, e.g.
  for a state or a secret. The bytes come from a secure source, and the
  text is in the URL-safe letters of base64."
  ([]
   (token 32))
  ([n]
   (bytes/base64url (bytes/random n))))

;; RFC 7636, section 4.2
(defn- code-challenge
  "The S256 code challenge of the PKCE code `verifier`."
  [verifier]
  (bytes/base64url (bytes/sha256 (bytes/encode verifier))))

;;; options

(def default-options
  "The default of each option that has one:

  - :profile-url-pred, profile-url?, the URLs that a user can sign in as,
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
  {:profile-url-pred profile-url?
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

;;; the providers

(def github-endpoints
  "The URLs of GitHub's OAuth endpoints and of the API's user."
  {:authorize "https://github.com/login/oauth/authorize"
   :token     "https://github.com/login/oauth/access_token"
   :account   "https://api.github.com/user"})

(def mastodon-paths
  "The paths of the OAuth endpoints and the API of a Mastodon server, which
  other servers with Mastodon's API share."
  {:authorize "/oauth/authorize"
   :token     "/oauth/token"
   :account   "/api/v1/accounts/verify_credentials"
   :apps      "/api/v1/apps"
   :metadata  "/.well-known/oauth-authorization-server"})

(defn- endpoint
  "The URL of the endpoint `k` of the provider of the `account`."
  [{:keys [provider instance] :as account} k]
  (case provider
    :github   (github-endpoints k)
    :mastodon (str instance (mastodon-paths k))))

(defn github-account
  "The GitHub account at the URL `href` of a rel=me link, as a map of the
  :provider :github, the :username and the :url of its profile, or nil when
  it's not a GitHub profile.

      (github-account \"https://github.com/simongray\")
      ;; => {:provider :github
      ;;     :username \"simongray\"
      ;;     :url      \"https://github.com/simongray\"}"
  [href]
  (when-let [[_ username] (re-matches #"(?i)https?://(?:www\.)?github\.com/([a-z0-9-]+)/?"
                                      (str href))]
    {:provider :github
     :username username
     :url      (str "https://github.com/" username)}))

;; Servers with Mastodon's API, e.g. GoToSocial, have profiles at /@ too.
;; TODO: recognise those at other paths, e.g. Pixelfed's /ann and the
;; /users/ann of Pleroma and Akkoma, by asking each host its software with
;; NodeInfo during discovery, and keeping the answers, also the noes, in a
;; store with an expiry.
(defn mastodon-account
  "The account on a Mastodon server at the URL `href` of a rel=me link, as
  a map of the :provider :mastodon, the :instance, the :username and the
  :url of its profile, or nil when it's not shaped like a Mastodon profile.

  The instance is the origin of the server, always on https, since
  nothing about it is known until it answers.

      (mastodon-account \"https://indieweb.social/@simongray\")
      ;; => {:provider :mastodon
      ;;     :instance \"https://indieweb.social\"
      ;;     :username \"simongray\"
      ;;     :url      \"https://indieweb.social/@simongray\"}"
  [href]
  (when-let [[_ authority username] (re-matches #"(?i)https?://([^/?#@\s]+)/@([a-z0-9_]+)/?"
                                                (str href))]
    (let [instance (str "https://" (str/lower-case authority))]
      {:provider :mastodon
       :instance instance
       :username username
       :url      (str instance "/@" username)})))

(defn- hrefs
  "The hrefs of the a elements in the HTML `s`."
  [s]
  (for [node  (mapcat #(tree-seq vector? (partial drop 2) %) (html/parse (str s)))
        :when (and (vector? node) (= :a (first node)))
        :let  [href (:href (second node))]
        :when href]
    href))

(defn account-links
  "The URLs that the `info` of an account of `provider` links to as the
  account's website: GitHub's website field, or the links in a Mastodon
  bio and in its profile fields. The info is the JSON of the provider's
  API, as a map."
  [provider info]
  (case provider
    :github   [(:blog info)]
    :mastodon (mapcat hrefs (cons (:note info) (map :value (:fields info))))))

(defn- signed-in-username
  "The username of the account of `provider` in its `info`."
  [provider info]
  (case provider
    :github   (:login info)
    :mastodon (:username info)))

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
       (keep #(or (github-account %) (mastodon-account %)))
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
        me           (canonical-url url)
        problem      (cond
                       (not (and me (profile-url-pred me)))
                       (requests/failure ::invalid-url
                                         (str "Not a profile URL: " url)
                                         {:url url})

                       (and (not silo-urls?)
                            (or (github-account me) (mastodon-account me)))
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
                         (keep canonical-url)
                         distinct
                         vec)
          :accounts (accounts response opts)})))))

;;; Mastodon's registrations

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

(defn- current?
  "Whether the `registration` is for the `redirect-uri` and doesn't expire
  before the instant `at`."
  [{:keys [expires] :as registration} redirect-uri at]
  (and (= redirect-uri (:redirect-uri registration))
       (or (nil? expires) (< (inst-ms at) (inst-ms expires)))))

(defn- stored!
  "The registration at the `instance` that the :registrations of the
  :mastodon of `opts` hold for the :redirect-uri of `opts`, or nil."
  [instance {:keys [mastodon redirect-uri now-fn] :as opts}]
  (async/then ((:get (:registrations mastodon)) instance)
              (fn [registration]
                (when (and registration
                           (current? registration redirect-uri (now-fn)))
                  (update registration :client-secret secret/hide)))))

;; Mastodon 4.3 added the profile scope, which reads the account alone, and
;; the metadata that lists it. Older servers take read:accounts.
(defn- scope!
  "The scope that reads the account of the user at the `instance`, by
  `opts`: profile when the server's metadata lists it, and else
  read:accounts."
  [instance {:keys [max-json-bytes] :as opts}]
  (async/then (requests/fetch! (str instance (:metadata mastodon-paths))
                      "application/json" max-json-bytes opts)
              (fn [{:keys [body]}]
                (if (some #{"profile"} (:scopes_supported (json/read-object body)))
                  "profile"
                  "read:accounts"))))

(defn- instant
  "The instant `seconds` after the epoch."
  [seconds]
  #?(:clj  (java.util.Date. (long (* 1000 seconds)))
     :cljs (js/Date. (* 1000 seconds))))

(defn- register!
  "Register your app at the Mastodon `instance` for the `scope`, by `opts`,
  and give the registration, or a map of the :error."
  [instance scope {:keys [mastodon redirect-uri] :as opts}]
  (let [{:keys [client-name website]} mastodon]
    (requests/and-then
     (requests/exchange! (requests/form-request (str instance (:apps mastodon-paths))
                              [["client_name" (or client-name
                                                  (url/host redirect-uri))]
                               ["redirect_uris" redirect-uri]
                               ["scopes" scope]
                               ["website" website]])
                opts)
     (fn [response]
       (let [{:keys [client_id client_secret client_secret_expires_at]
              :as   answer} (requests/json-answer ::registration-error response)]
         (cond
           (:error answer)
           (update answer :error assoc :instance instance)

           (not (and (string? client_id) (string? client_secret)))
           (requests/failure ::registration-error "The server gave no client credentials"
                    {:instance instance})

           :else
           (cond-> {:client-id     client_id
                    :client-secret (secret/hide client_secret)
                    :scope         scope
                    :redirect-uri  redirect-uri}
             (pos-int? client_secret_expires_at)
             (assoc :expires (instant client_secret_expires_at)))))))))

;; Mastodon's API: POST /api/v1/apps, once for each server
(defn registration!
  "Give the registration of your app at the Mastodon `instance`, by `opts`:
  the one in the :registrations store of their :mastodon for their
  :redirect-uri, or else a new one, which goes to the store. A failure
  gives a map of the :error. In ClojureScript, it gives a promise.

  A new registration has the scope profile, which reads the account alone,
  when the server's metadata lists it, and else read:accounts. The
  :mastodon of `opts` can also have the :client-name to show the user,
  the domain of the redirect URL by default, and the :website of your
  app."
  [instance {:keys [mastodon] :as opts}]
  (let [opts  (merge default-options opts)
        store (:registrations mastodon)]
    (async/then
     (stored! instance opts)
     (fn [registration]
       (or registration
           (-> (scope! instance opts)
               (async/then #(register! instance % opts))
               (requests/and-then (fn [registration]
                           (async/then ((:put! store) instance registration)
                                       (constantly registration))))))))))

;;; signing in

(def ^:no-doc session-kind
  "The kind of a signed state that carries a session."
  ::session)

(defn- fingerprint
  "The SHA-256 of the text `s` in the URL-safe letters of base64."
  [s]
  (bytes/base64url (bytes/sha256 (bytes/encode s))))

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

(defn- request-problem
  "What's wrong with `opts` for signing in with the `account`, or nil."
  [{:keys [provider] :as account} {:keys [redirect-uri] :as opts}]
  (let [{:keys [client-id client-secret registrations]} (get opts provider)]
    (cond
      (not (url/web-url? redirect-uri))
      "The :redirect-uri isn't an http or https URL"

      (and (= :github provider) (not (and client-id client-secret)))
      "The :github needs the :client-id and :client-secret of your OAuth app"

      (and (= :mastodon provider) (not registrations))
      "The :mastodon needs a store of :registrations"

      (not (#{:github :mastodon} provider))
      "The account isn't at a provider of RelMeAuth")))

(defn- client!
  "The client of your app at the provider of the `account`, by `opts`: the
  :github of `opts`, or the registration! at the Mastodon server."
  [{:keys [provider instance] :as account} opts]
  (case provider
    :github   (:github opts)
    :mastodon (registration! instance opts)))

(defn- authorization-url
  "The URL at the provider of the `session` that asks the user to sign in
  for the `client-id`."
  [{:keys [account redirect-uri scope state code-verifier] :as session}
   client-id]
  (url/with-query (endpoint account :authorize)
    (concat [["response_type" "code"]
             ["client_id" client-id]
             ["redirect_uri" redirect-uri]
             ["state" state]
             ["code_challenge" (code-challenge code-verifier)]
             ["code_challenge_method" "S256"]]
            (case (:provider account)
              :github   [["login" (:username account)]
                         ["allow_signup" "false"]]
              :mastodon [["scope" scope]]))))

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
    the options of registration!
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
    (when-let [problem (request-problem account opts)]
      (throw (ex-info problem {:account account :redirect-uri redirect-uri})))
    (requests/and-then
     (client! account opts)
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
         {:url     (authorization-url session client-id)
          :session session})))))

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

(defn- redeeming-client!
  "The client that redeems the code of the `session`, by `opts`: the
  :github of `opts`, or the stored registration at the Mastodon server, or
  a map of the :error."
  [{:keys [account] :as session} opts]
  (case (:provider account)
    :github   (:github opts)
    :mastodon (async/then (stored! (:instance account) opts)
                          #(or % (requests/failure ::not-registered
                                          (str "The app has no registration at "
                                               (:instance account))
                                          {:instance (:instance account)})))))

;; RFC 6749, section 4.1.3; RFC 7636, section 4.5
(defn- access-token!
  "The access token for the `code` of the `session`, redeemed by the
  `client` with `opts`, as a map of the :access-token, or of the :error."
  [{:keys [account redirect-uri code-verifier] :as session}
   {:keys [client-id client-secret] :as client}
   code
   opts]
  (requests/and-then
   (requests/exchange! (requests/form-request (endpoint account :token)
                            [["grant_type" "authorization_code"]
                             ["code" code]
                             ["client_id" client-id]
                             ["client_secret" (secret/reveal client-secret)]
                             ["redirect_uri" redirect-uri]
                             ["code_verifier" code-verifier]])
              opts)
   (fn [response]
     (let [{:keys [access_token] :as answer} (requests/json-answer ::token-error response)]
       (cond
         (:error answer)        answer
         (string? access_token) {:access-token (secret/hide access_token)}
         :else                  (requests/failure ::token-error
                                         "The provider gave no access token"))))))

(defn- account-info!
  "The JSON of the account of the `session` that the `access-token` reads,
  by `opts`, as a map, or a map of the :error."
  [{:keys [account] :as session} access-token opts]
  (requests/and-then
   (requests/exchange! {:url     (endpoint account :account)
               :headers (merge {"Authorization" (http/authorization {:token access-token})}
                               (case (:provider account)
                                 :github   {"Accept"               "application/vnd.github+json"
                                            "X-GitHub-Api-Version" "2022-11-28"}
                                 :mastodon {"Accept" "application/json"}))}
              opts)
   #(requests/json-answer ::account-error %)))

(defn- trimmed
  "The canonical `url` without a slash at the end of its path, unless the
  path is /."
  [url]
  (str/replace url #"^(https?://[^/?#]*/[^?#]*[^/?#])/(?=[?#]|$)" "$1"))

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
         signed-in                   (signed-in-username provider info)
         same                        (if trim-slash? trimmed identity)
         links                       (keep #(some-> (canonical-url %) same)
                                           (account-links provider info))]
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
      (-> (redeeming-client! session opts)
          (requests/and-then #(access-token! session % (param params "code") opts))
          (requests/and-then #(account-info! session (:access-token %) opts))
          (requests/and-then (fn [info]
                      (if-let [problem (account-problem session info opts)]
                        {:error problem}
                        {:me me :account account})))))))
