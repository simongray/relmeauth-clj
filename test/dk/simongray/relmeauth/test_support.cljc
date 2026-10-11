(ns dk.simongray.relmeauth.test-support
  "What the tests share: a test of steps that give promises in
  ClojureScript, a network of Ring handlers in memory that answers as the
  sites of the tests would, GitHub and a Mastodon server among them, and
  on the JVM a server of Ring handlers on localhost.

  The network, the pages and the server on localhost are those of
  indieauth-clj's test support."
  (:require [clojure.string :as str]
            #?(:cljs [clojure.test :refer [is async]])
            [dk.simongray.relmeauth :as relmeauth]
            [dk.simongray.relmeauth.bytes :as bytes]
            [dk.simongray.relmeauth.json :as json]
            [dk.simongray.relmeauth.providers :as providers]
            [dk.simongray.wary-fetch :as http]
            [dk.simongray.wary-fetch.async :as async]
            #?(:clj [dk.simongray.wary-fetch.headers :as headers])
            [dk.simongray.wary-fetch.url :as url])
  #?(:clj (:import [com.sun.net.httpserver HttpExchange HttpHandler HttpServer]
                   [java.net InetSocketAddress]
                   [java.util.concurrent Executors])))

(defn run
  "Run the steps `fs` one after another as a test on either platform. Each
  step is a function of no arguments that gives a value or a promise.

  In ClojureScript, a deftest runs only the async test that it returns. So
  a deftest calls `run` once, as its last form, with all its steps."
  [& fs]
  #?(:clj  (doseq [f fs] (f))
     :cljs (async done
             (-> (reduce (fn [p f] (.then p (fn [_] (f)))) (js/Promise.resolve nil) fs)
                 (.catch (fn [e] (is false (str "rejected: " e))))
                 (.finally done)))))

(defn- url-parts
  "The :scheme, :authority, :host, :port, :path and :query of the `url`, as
  plain as the URLs of the tests are."
  [url]
  (let [[_ scheme authority path query] (re-matches #"([a-z]+)://([^/?#]*)([^?#]*)(?:\?([^#]*))?.*"
                                                    url)
        [_ host port]                   (re-matches #"([^:]*)(?::(\d+))?" authority)]
    {:scheme    scheme
     :authority authority
     :host      host
     :port      port
     :path      path
     :query     query}))

(defn ring-request
  "The Ring request of the wary-fetch `request` map."
  [{:keys [method url headers body]}]
  (let [{:keys [scheme host port path query]} (url-parts url)]
    {:request-method (or method :get)
     :scheme         (keyword scheme)
     :server-name    host
     :server-port    (if port (parse-long port) (if (= "https" scheme) 443 80))
     :uri            (if (empty? path) "/" path)
     :query-string   query
     :headers        (into {} (for [[k v] headers] [(str/lower-case (name k)) (str v)]))
     :body           body}))

(defn- fetched
  "The wary-fetch response from `url` of the Ring `response`."
  [url {:keys [status headers body]}]
  {:status  status
   :url     url
   :headers (into {} (for [[k v] headers] [(str/lower-case k) v]))
   :body    (if (string? body) body (some-> body str))})

(defn- without-query
  "The `url` without its query and fragment."
  [url]
  (first (str/split url #"[?#]" 2)))

(defn- host-of
  "The host and port of the `url`."
  [url]
  (:authority (url-parts url)))

(defn- with-cookies
  "The `cookies`, a map of names to values, with those that the Set-Cookie
  value `v`, a text or texts, sets."
  [cookies v]
  (into (or cookies {})
        (for [s     (if (sequential? v) v [v])
              :let  [[_ k value] (re-find #"^\s*([^=;\s]+)=([^;]*)" (str s))]
              :when k]
          [k value])))

(defn- cookie-header
  "The Cookie header of the `cookies`, a map of names to values, or nil."
  [cookies]
  (some->> (seq cookies)
           (map (fn [[k v]] (str k "=" v)))
           (str/join "; ")))

(defn network
  "A function that sends a request map as http/send! does, to the Ring
  handler that `routes`, a map of URLs without their query, has for its
  URL, and else answers 404. It follows redirects as http/send! does,
  keeps the cookies of each host as a browser does, and conj's each
  request to the atom `log`, as the Ring request with its :url."
  ([routes]
   (network routes (atom [])))
  ([routes log]
   (let [jar (atom {})]
     (fn send [request]
       (let [request (http/revealed request)
             limit   (:max-redirects request 5)]
         (letfn [(step [request chain]
                   (let [host   (host-of (:url request))
                         cookie (cookie-header (get @jar host))
                         ring   (cond-> (assoc (ring-request request) :url (:url request))
                                  cookie (assoc-in [:headers "cookie"] cookie))
                         h      (get routes (without-query (:url request))
                                     (constantly {:status 404 :headers {} :body ""}))]
                     (swap! log conj ring)
                     (async/then
                      (h ring)
                      (fn [response]
                        (let [{:keys [status headers] :as r} (fetched (:url request) response)
                              location                       (get headers "location")]
                          (when-let [v (get headers "set-cookie")]
                            (swap! jar update host with-cookies v))
                          (if (and (#{301 302 303 307 308} status)
                                   location
                                   (< (count chain) limit))
                            (step (cond-> (assoc request :url (url/absolute-url (:url request) location))
                                    (= 303 status) (assoc :method :get :body nil))
                                  (conj chain [status (:url request) headers]))
                            (cond-> r
                              (seq chain) (assoc :redirects chain))))))))]
           (step request [])))))))

(defn page
  "A Ring handler that answers with the HTML `s`."
  [s]
  (constantly {:status  200
               :headers {"Content-Type" "text/html; charset=utf-8"}
               :body    s}))

(defn json-response
  "The Ring response with the JSON of `x`, with the `status`, 200 by
  default."
  ([x]
   (json-response 200 x))
  ([status x]
   {:status  status
    :headers {"Content-Type" "application/json"}
    :body    (json/write-json x)}))

(defn redirect
  "A Ring handler that redirects with `status` to `url`."
  [status url]
  (constantly {:status status :headers {"Location" url} :body ""}))

(defn query
  "The query parameters of the `url`, as a map by name."
  [url]
  (url/query-params (second (re-find #"\?([^#]*)" url))))

(defn- form
  "The fields of the form that the Ring `request` posts, as a map by name."
  [{:keys [body] :as request}]
  (url/query-params (if (string? body) body #?(:clj (slurp body) :cljs ""))))

(defn- bearer
  "The token of the Authorization header of the Ring `request`, or nil."
  [request]
  (second (re-matches #"Bearer (.+)" (str (get-in request [:headers "authorization"])))))

(defn- found
  "The Ring response that sends the browser to `url` with the `params`."
  [url params]
  {:status 302 :headers {"Location" (url/with-query url params)} :body ""})

(defn- verified?
  "Whether the PKCE `verifier` is that of the S256 `challenge`."
  [verifier challenge]
  (= challenge (bytes/base64url (bytes/sha256 (bytes/encode (str verifier))))))

;;; a provider

;; The two providers differ in their URLs, their answers and how they
;; register apps, and share the rest: a user signed in at the provider who
;; says yes, codes that work once, PKCE and bearer tokens.

(defn- authorize
  "A Ring handler of the authorization endpoint of the `provider`, an atom,
  that sends the browser back with a code, or with access_denied when the
  user says no, unless `client-problem` of the request gives a problem."
  [provider client-problem]
  (fn [{:keys [query-string] :as request}]
    (let [{:strs [client_id redirect_uri state code_challenge code_challenge_method]
           :as   params} (url/query-params query-string)
          {:keys [signed-in deny?]} @provider]
      (cond
        (or (client-problem params) (not= "S256" code_challenge_method))
        {:status 400 :headers {} :body (str (client-problem params))}

        deny?
        (found redirect_uri [["error" "access_denied"] ["state" state]])

        :else
        (let [code (relmeauth/token)]
          (swap! provider assoc-in [:codes code] {:client-id    client_id
                                                   :redirect-uri redirect_uri
                                                   :challenge    code_challenge
                                                   :username     signed-in})
          (found redirect_uri [["code" code] ["state" state]]))))))

(defn- token-answer
  "The answer of the token endpoint of a provider with the atom `provider`
  to the `fields` of a client whose secret is `known`, as a map of the
  :access_token or of the :error. A code works once."
  ;; known, since client-secret and client_secret are one name in JavaScript
  [provider {:strs [client_id client_secret code redirect_uri code_verifier] :as fields} known]
  (let [entry (get-in @provider [:codes code])]
    (swap! provider update :codes dissoc code)
    (cond
      (or (nil? known) (not= known client_secret))
      {:error "invalid_client"}

      (not (and entry
                (= client_id (:client-id entry))
                (= redirect_uri (:redirect-uri entry))
                (verified? code_verifier (:challenge entry))))
      {:error "invalid_grant"}

      :else
      (let [token (relmeauth/token)]
        (swap! provider assoc-in [:tokens token] (:username entry))
        {:access_token token :token_type "Bearer"}))))

(defn- account-response
  "The Ring response to the `request` for the account of its token at a
  provider with the atom `provider`, whose accounts are the map `accounts`
  by username."
  [provider accounts request]
  (if-let [username (get-in @provider [:tokens (bearer request)])]
    (json-response (get accounts username))
    (json-response 401 {:error "The access token is invalid"})))

;;; GitHub

(defn github
  "The routes of GitHub with the `apps`, client ids to secrets, and the
  `accounts`, usernames to their JSON, and the atom of its state, with the
  user who is :signed-in and :deny?, as a pair."
  [apps accounts]
  (let [provider (atom {:signed-in (key (first accounts))})]
    [{(:authorize providers/github-endpoints)
      (authorize provider (fn [{:strs [client_id]}]
                            (when-not (contains? apps client_id)
                              "The client_id is unknown")))

      (:token providers/github-endpoints)
      (fn [request]
        (let [fields (form request)]
          (json-response (token-answer provider fields (get apps (get fields "client_id"))))))

      (:account providers/github-endpoints)
      (fn [request]
        (if (= "2022-11-28" (get-in request [:headers "x-github-api-version"]))
          (account-response provider accounts request)
          (json-response 400 {:message "No API version"})))}
     provider]))

;;; a Mastodon server

(defn mastodon
  "The routes of a Mastodon server at the `instance` with the `accounts`,
  usernames to their JSON, and the atom of its state, with the user who is
  :signed-in, :deny? and the :apps, as a pair. The `opts` are
  :profile-scope?, for Mastodon 4.3 or later, and :refuse? to register."
  [instance accounts {:keys [profile-scope? refuse?] :as opts}]
  (let [provider (atom {:signed-in (key (first accounts)) :apps {}})
        scopes   (cond-> #{"read" "read:accounts"} profile-scope? (conj "profile"))
        path     #(str instance (get providers/mastodon-paths %))]
    [(cond->
      {(path :apps)
       (fn [request]
         (let [{:strs [client_name redirect_uris] :as fields} (form request)
               asked (str/split (get fields "scopes" "read") #" ")]
           (cond
             refuse?
             {:status 404 :headers {} :body "Not Mastodon"}

             (not (and (seq client_name) (seq redirect_uris) (every? scopes asked)))
             (json-response 422 {:error "Validation failed"})

             :else
             (let [id     (relmeauth/token)
                   secret (relmeauth/token)]
               (swap! provider assoc-in [:apps id] {:secret       secret
                                                     :redirect-uri redirect_uris
                                                     :scopes       (set asked)})
               (json-response {:id                       "1"
                               :name                     client_name
                               :redirect_uris            [redirect_uris]
                               :client_id                id
                               :client_secret            secret
                               :client_secret_expires_at 0})))))

       (path :authorize)
       (authorize provider (fn [{:strs [client_id redirect_uri scope]}]
                             (let [app (get-in @provider [:apps client_id])]
                               (cond
                                 (nil? app)
                                 "The client_id is unknown"

                                 (not= redirect_uri (:redirect-uri app))
                                 "The redirect_uri isn't registered"

                                 (not (every? (:scopes app) (str/split (str scope) #" ")))
                                 "The scope isn't registered"))))

       (path :token)
       (fn [request]
         (let [fields (form request)
               secret (get-in @provider [:apps (get fields "client_id") :secret])
               answer (token-answer provider fields secret)]
           (json-response (if (:error answer) 400 200) answer)))

       (path :account)
       #(account-response provider accounts %)}

      profile-scope?
      (assoc (path :metadata)
             (constantly (json-response {:issuer                           (str instance "/")
                                         :authorization_endpoint           (path :authorize)
                                         :token_endpoint                   (path :token)
                                         :app_registration_endpoint        (path :apps)
                                         :scopes_supported                 (sort scopes)
                                         :code_challenge_methods_supported ["S256"]}))))
     provider]))

(defn authorize!
  "Send the browser to the authorization `url` with `send`, as a user who
  is signed in at the provider and says yes, and give the query
  parameters that it comes back to the client with."
  [send url]
  (async/then (send {:url url :max-redirects 0})
              (fn [{:keys [status headers body]}]
                (if (= 302 status)
                  (query (get headers "location"))
                  {"error" (str "The provider answered " status ": " body)}))))

#?(:clj
   (defn- exchange-request
     "The Ring request of the JDK server's `exchange`."
     [^HttpExchange exchange]
     (let [uri (.getRequestURI exchange)]
       {:request-method (keyword (str/lower-case (.getRequestMethod exchange)))
        :uri            (.getPath uri)
        :query-string   (.getRawQuery uri)
        :scheme         :http
        :headers        (into {}
                              (for [[k vs] (.getRequestHeaders exchange)]
                                [(str/lower-case k) (str/join ", " vs)]))
        :body           (.getRequestBody exchange)})))

#?(:clj
   (defn- respond!
     "Answer the JDK server's `exchange` with the Ring `response`."
     [^HttpExchange exchange {:keys [status headers body]}]
     (let [^bytes b (if (bytes? body) body (.getBytes (str body) "UTF-8"))]
       (doseq [[k v] headers]
         (.add (.getResponseHeaders exchange) (str k) (str v)))
       ;; with the request body open, Java 11 closes the connection after
       ;; an answer with no body, and the client reuses it
       (.close (.getRequestBody exchange))
       (if (zero? (alength b))
         (.sendResponseHeaders exchange status -1)
         (do (.sendResponseHeaders exchange status (alength b))
             (with-open [out (.getResponseBody exchange)]
               (.write out b))))
       (.close exchange))))

#?(:clj
   (defn with-server
     "Call `f` with the URL of a server on localhost that answers each
     request by the Ring handler that `handlers`, a map of paths, has for
     its path, or with 404."
     [handlers f]
     (let [server (HttpServer/create (InetSocketAddress. "127.0.0.1" 0) 0)]
       (.createContext server "/"
                       (reify HttpHandler
                         (handle [_ exchange]
                           (let [request (exchange-request exchange)
                                 h       (get handlers (:uri request))]
                             (respond! exchange
                                       (if h
                                         (h request)
                                         {:status 404 :headers {} :body ""}))))))
       ;; a thread for each exchange, since a handler can send a request
       ;; to the same server
       (.setExecutor server (Executors/newCachedThreadPool))
       (.start server)
       (try
         (f (str "http://127.0.0.1:" (.getPort (.getAddress server))))
         (finally
           (.stop server 0))))))

#?(:clj
   (defn- forwarder
     "A Ring handler that sends each request on over HTTP to the server at
     `base`, under the path of its `host`, and answers with its response."
     [base host]
     (fn [{:keys [request-method uri query-string body] :as request}]
       (let [r (http/send! {:method        request-method
                            :url           (str base "/" host uri
                                                (some->> query-string (str "?")))
                            :headers       (dissoc (:headers request) "host" "content-length")
                            :body          body
                            :max-redirects 0
                            :allow-pred    (constantly true)})]
         {:status  (:status r)
          :headers (into {} (for [k (keys (:headers r))]
                              [k (headers/joined (:headers r) k)]))
          :body    (:body r)}))))

#?(:clj
   (defn on-localhost
     "Call `f` with `routes`, a map of URLs to Ring handlers, whose handlers
     send each request over HTTP to a server on localhost that runs the
     handler of its URL. So the requests of a test go over real HTTP, with
     the URLs of the sites of the test."
     [routes f]
     (let [local (into {} (for [[u h] routes
                                :let  [{:keys [authority path]} (url-parts u)]]
                            [(str "/" authority (if (empty? path) "/" path)) h]))]
       (with-server local
         (fn [base]
           (f (into {} (for [u (keys routes)]
                         [u (forwarder base (:authority (url-parts u)))]))))))))
