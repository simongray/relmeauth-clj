(ns ^:no-doc dk.simongray.relmeauth.providers
  "What differs between GitHub and the Mastodon servers: their accounts,
  their endpoints, the client of your app at each, and what their APIs say
  of an account. Your app registers at a Mastodon server the first time a
  user signs in there."
  (:require [clojure.string :as str]
            [dk.simongray.html-pieces :as html]
            [dk.simongray.indieauth :as indieauth]
            [dk.simongray.relmeauth :as-alias relmeauth]
            [dk.simongray.relmeauth.requests :as requests]
            [dk.simongray.wary-fetch :as http]
            [dk.simongray.wary-fetch.async :as async]
            [dk.simongray.wary-fetch.json :as json]
            [dk.simongray.wary-fetch.secret :as secret]
            [dk.simongray.wary-fetch.url :as url]))

;;; accounts

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

(defn endpoint
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
  The instance is the origin of the server, always on https.

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

(defn account
  "The account at GitHub or on a Mastodon server at the URL `href`, or
  nil."
  [href]
  (or (github-account href) (mastodon-account href)))

(defn links
  "The URLs that the `info` of an account of `provider` links to as the
  account's website: GitHub's website field, or the links in a Mastodon
  bio and in its profile fields. The info is the JSON of the provider's
  API, as a map."
  [provider info]
  (case provider
    :github   [(:blog info)]
    :mastodon (for [s                  (cons (:note info) (map :value (:fields info)))
                    [_ {:keys [href]}] (html/links (str s) {:link-tags #{:a}})]
                href)))

(defn username
  "The username of the account of `provider` in its `info`."
  [provider info]
  (case provider
    :github   (:login info)
    :mastodon (:username info)))

;;; Mastodon's registrations

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
                (if (some #{"profile"} (:scopes_supported (json/read-json body)))
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
  (let [{:keys [client-name website]} mastodon
        fields                        [["client_name" (or client-name
                                                          (url/host redirect-uri))]
                                       ["redirect_uris" redirect-uri]
                                       ["scopes" scope]
                                       ["website" website]]]
    (requests/and-then
     (requests/exchange! (requests/form-request (str instance (:apps mastodon-paths))
                                                fields)
                         opts)
     (fn [response]
       (let [{:keys [client_id client_secret client_secret_expires_at]
              :as   answer} (requests/json-answer ::relmeauth/registration-error
                                                  response)]
         (cond
           (:error answer)
           (update answer :error assoc :instance instance)

           (not (and (string? client_id) (string? client_secret)))
           (requests/failure ::relmeauth/registration-error
                             "The server gave no client credentials"
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
  "Give the registration of your app at the Mastodon `instance`, by `opts`
  over the defaults: the one in the store for the redirect URL, or else a
  new one, which goes to the store, or a map of the :error."
  [instance {:keys [mastodon] :as opts}]
  (async/then
   (stored! instance opts)
   (fn [registration]
     (or registration
         (-> (scope! instance opts)
             (async/then #(register! instance % opts))
             (requests/and-then
              (fn [registration]
                (async/then ((:put! (:registrations mastodon)) instance registration)
                            (constantly registration)))))))))

;;; the clients of your app

(defn request-problem
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

(defn client!
  "The client of your app at the provider of the `account`, by `opts` over
  the defaults: the :github of `opts`, or the registration! at the
  Mastodon server."
  [{:keys [provider instance] :as account} opts]
  (case provider
    :github   (:github opts)
    :mastodon (registration! instance opts)))

(defn redeeming-client!
  "The client that redeems the code of the `session`, by `opts` over the
  defaults: the :github of `opts`, or the stored registration at the
  Mastodon server for the session's redirect URL, which the code was
  given for, or a map of the :error."
  [{:keys [account redirect-uri] :as session} opts]
  (case (:provider account)
    :github   (:github opts)
    :mastodon (async/then (stored! (:instance account)
                                   (assoc opts :redirect-uri redirect-uri))
                          #(or % (requests/failure ::relmeauth/not-registered
                                                   (str "The app has no registration at "
                                                        (:instance account))
                                                   {:instance (:instance account)})))))

;;; OAuth

;; RFC 6749, section 4.1.1; RFC 7636, section 4.3
(defn authorization-url
  "The URL at the provider of the `session` that asks the user to sign in
  for the `client-id`."
  [{:keys [account redirect-uri scope state code-verifier] :as session}
   client-id]
  (url/with-query (endpoint account :authorize)
    (concat [["response_type" "code"]
             ["client_id" client-id]
             ["redirect_uri" redirect-uri]
             ["state" state]
             ["code_challenge" (indieauth/code-challenge code-verifier)]
             ["code_challenge_method" "S256"]]
            (case (:provider account)
              :github   [["login" (:username account)]
                         ["allow_signup" "false"]]
              :mastodon [["scope" scope]]))))

;; RFC 6749, section 4.1.3; RFC 7636, section 4.5
(defn access-token!
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
     (let [{:keys [access_token]
            :as   answer} (requests/json-answer ::relmeauth/token-error response)]
       (cond
         (:error answer)        answer
         (string? access_token) {:access-token (secret/hide access_token)}
         :else                  (requests/failure ::relmeauth/token-error
                                                  "The provider gave no access token"))))))

(defn account-info!
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
   #(requests/json-answer ::relmeauth/account-error %)))
