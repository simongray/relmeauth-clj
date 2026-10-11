(ns dk.simongray.relmeauth.end-to-end-test
  "An app that signs its owner in with RelMeAuth, as an IndieAuth server
  signs in its user, with a browser in between. The session goes through
  the browser in a signed cookie, and nothing is kept but Mastodon's
  registrations. On the JVM, the requests go over HTTP on localhost too."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [dk.simongray.relmeauth :as relmeauth]
            [dk.simongray.relmeauth.test-support :as t :refer [run]]
            [dk.simongray.wary-fetch.async :as async]
            [dk.simongray.wary-fetch.secret :as secret]
            [dk.simongray.wary-fetch.url :as url]))

(def secret-text "a secret of thirty-two bytes, at least")

(def owner "https://user.example/")

(defn- cookie
  "The value of the cookie `k` of the Ring `request`, or nil."
  [request k]
  (some (fn [part]
          (let [[name value] (str/split (str/trim part) #"=" 2)]
            (when (= k name) value)))
        (str/split (str (get-in request [:headers "cookie"])) #";")))

(defn- text
  "The Ring response of `status` with the text `s`."
  [status s]
  {:status status :headers {"Content-Type" "text/plain"} :body s})

(defn- app
  "The Ring handlers of the app at https://app.example/, which signs in the
  owner of https://user.example/ with the network in the atom `net`."
  [net]
  (let [opts {:send         #(@net %)
              :redirect-uri "https://app.example/callback"
              :secret       secret-text
              :github       {:client-id "gh-id" :client-secret (secret/hide "gh-secret")}
              :mastodon     {:registrations (relmeauth/memory-store)
                             :client-name   "The app"}}]
    {"https://app.example/sign-in"
     (fn [{:keys [query-string]}]
       (let [provider (keyword (get (url/query-params query-string) "with"))]
         (async/then
          (relmeauth/discover! owner opts)
          (fn [{:keys [accounts] :as discovery}]
            (async/then
             (relmeauth/authorization-request! discovery
                                               (first (filter #(= provider (:provider %)) accounts))
                                               (assoc opts :data {:request "the request of a Micropub app"}))
             (fn [{:keys [url session]}]
               {:status  302
                :headers {"Location"   url
                          "Set-Cookie" (str "signin=" (:cookie session) "; Path=/; HttpOnly; Secure; SameSite=Lax")}
                :body    ""}))))))

     "https://app.example/callback"
     (fn [{:keys [query-string] :as request}]
       (let [params  (url/query-params query-string)
             session (relmeauth/state-session secret-text (get params "state") (cookie request "signin"))]
         (if-not session
           (text 403 "This browser didn't start the sign-in")
           (async/then (relmeauth/redeem! session params opts)
                       (fn [{:keys [me error]}]
                         (if (= owner me)
                           (text 200 (str "Signed in as " me " for " (get-in session [:data :request])))
                           (text 403 (str "Not signed in: " (:reason error)))))))))}))

(def ann-at-github
  {:login "ann" :blog "https://user.example"})

(def ann-at-mastodon
  {:username "ann"
   :note     "<p>Hi</p>"
   :fields   [{:name "Site" :value "<a href=\"https://user.example/\" rel=\"me\">user.example</a>"}]})

(defn- routes
  "The routes of the app, the owner's site, GitHub and a Mastodon server,
  with the network in the atom `net`."
  [net]
  (merge (app net)
         (first (t/github {"gh-id" "gh-secret"} {"ann" ann-at-github}))
         (first (t/mastodon "https://social.example" {"ann" ann-at-mastodon} {:profile-scope? true}))
         {owner (t/page (str "<a rel=me href=https://github.com/ann>GitHub</a>"
                             "<a rel=me href=https://social.example/@ann>Mastodon</a>"))}))

(defn- steps
  "The steps of the test of the network in the atom `net` and its `routes`."
  [net routes]
  (let [other (t/network routes)]
    [#(async/then (@net {:url "https://app.example/sign-in?with=github"})
                  (fn [{:keys [status body]}]
                    (is (= 200 status))
                    (is (= "Signed in as https://user.example/ for the request of a Micropub app" body))))
     #(async/then (@net {:url "https://app.example/sign-in?with=mastodon"})
                  (fn [{:keys [status body]}]
                    (is (= 200 status))
                    (is (= "Signed in as https://user.example/ for the request of a Micropub app" body))))
     (fn []
       (testing "only the browser that started the sign-in can finish it"
         (-> (@net {:url "https://app.example/sign-in?with=github" :max-redirects 0})
             (async/then #(@net {:url (get-in % [:headers "location"]) :max-redirects 0}))
             (async/then #(other {:url (get-in % [:headers "location"])}))
             (async/then (fn [{:keys [status]}] (is (= 403 status)))))))]))

(deftest signing-in-the-owner
  (let [net (atom nil)
        rs  (routes net)]
    (reset! net (t/network rs))
    (apply run (steps net rs))))

#?(:clj
   (deftest signing-in-the-owner-over-http
     (let [net (atom nil)]
       (t/on-localhost (routes net)
                       (fn [rs]
                         (reset! net (t/network rs))
                         (apply run (steps net rs)))))))
