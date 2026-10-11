(ns dk.simongray.relmeauth-test
  "RelMeAuth: the URLs, the accounts of rel=me links, discovery, the
  checks of the account that signed in, and signing in at GitHub and at a
  Mastodon server, with the providers of the test support."
  (:require [clojure.string :as str]
            [clojure.test :refer [deftest is testing]]
            [dk.simongray.relmeauth :as relmeauth]
            [dk.simongray.relmeauth.test-support :as t :refer [run]]
            [dk.simongray.wary-fetch.async :as async]
            [dk.simongray.wary-fetch.secret :as secret]))

(deftest profile-urls
  (testing "IndieAuth 3.2"
    (doseq [s ["https://example.com/" "https://example.com/username" "https://example.com/users?id=100"]]
      (is (relmeauth/profile-url? s) s))
    (doseq [s ["example.com" "mailto:user@example.com" "https://example.com/foo/../bar" "https://example.com/#me"
               "https://user:pass@example.com/" "https://example.com:8443/" "https://172.28.92.51/"
               "https://example.com/a/%2E%2e/b" "https://[::1]/" "https://a b.example/" "https:///x" nil]]
      (is (not (relmeauth/profile-url? s)) (pr-str s)))))

(deftest canonical-urls
  (testing "IndieAuth 3.4"
    (is (= "https://example.com/" (relmeauth/canonical-url "https://example.com")))
    (is (= "https://example.com/" (relmeauth/canonical-url "HTTPS://Example.COM")))
    (is (= "https://example.com/" (relmeauth/canonical-url " example.com ")) "a host alone, as in GitHub's website field")
    (is (= "http://example.com/" (relmeauth/canonical-url "http://example.com:80"))))
  (testing "nothing else changes, so a path compares as it's written"
    (is (= "https://example.com/Me/" (relmeauth/canonical-url "https://example.com/Me/")))
    (is (not= (relmeauth/canonical-url "https://example.com/me/") (relmeauth/canonical-url "https://example.com/me"))))
  (is (nil? (relmeauth/canonical-url "mailto:user@example.com")))
  (is (nil? (relmeauth/canonical-url "/relative")))
  (is (nil? (relmeauth/canonical-url "")))
  (is (nil? (relmeauth/canonical-url nil))))

(deftest accounts-of-links
  (testing "a GitHub profile"
    (is (= {:provider :github :username "JaneDoe" :url "https://github.com/JaneDoe"}
           (relmeauth/github-account "https://github.com/JaneDoe")))
    (is (= "janedoe" (:username (relmeauth/github-account "http://www.github.com/janedoe/")))))
  (testing "other GitHub pages"
    (doseq [href ["https://github.com/janedoe/some-repo" "https://github.com/" "https://github.com/janedoe?tab=repositories"
                  "https://gist.github.com/janedoe" "https://github.com.evil.example/janedoe"]]
      (is (nil? (relmeauth/github-account href)) href)))
  (testing "a profile on a Mastodon server, which is on https"
    (is (= {:provider :mastodon :instance "https://indieweb.social" :username "simongray"
            :url "https://indieweb.social/@simongray"}
           (relmeauth/mastodon-account "http://IndieWeb.Social/@simongray/"))))
  (testing "other pages"
    (doseq [href ["https://example.com/@a/b" "https://example.com/users/a" "https://indieweb.social/@ann@other.example"
                  "https://user@example.com/@ann" "https://github.com/simongray" "/@ann"]]
      (is (nil? (relmeauth/mastodon-account href)) href))))

(def page
  "A page that names accounts with rel=me, and links that don't."
  "<html><head><link rel='me' href='https://github.com/ann'></head>
   <body>
     <a href='https://github.com/not-rel-me'>a link</a>
     <a rel='me nofollow' href='https://social.example/@ann'>Mastodon</a>
     <a rel='ME' href='https://example.net/ann'>another site</a>
     <a rel='me' href='/@ann'>here</a>
     <a rel='me' href='https://github.com/ann/'>GitHub again</a>
   </body></html>")

(deftest accounts-of-a-page
  (let [response {:url "https://user.example/" :headers {"content-type" "text/html"} :body page}]
    (testing "in the order of the page, once each, from a and link elements anywhere"
      (is (= [{:provider :github :username "ann" :url "https://github.com/ann"}
              {:provider :mastodon :instance "https://social.example" :username "ann" :url "https://social.example/@ann"}
              {:provider :mastodon :instance "https://user.example" :username "ann" :url "https://user.example/@ann"}]
             (relmeauth/accounts response {:github {} :mastodon {}}))))
    (testing "at the providers that the options set up"
      (is (= [:github] (map :provider (relmeauth/accounts response {:github {}}))))
      (is (= [] (relmeauth/accounts response {}))))
    (testing "not of a page that isn't HTML"
      (is (= [] (relmeauth/accounts (assoc response :headers {"content-type" "application/json"}) {:github {}}))))))

(def ann-at-github
  "The account of the user at GitHub, as GitHub's API has it."
  {:login "Ann" :html_url "https://github.com/Ann" :blog "user.example"})

(def ann-at-mastodon
  "The account of the user at the Mastodon server, as its API has it."
  {:username "ann"
   :url      "https://social.example/@ann"
   :note     "<p>I write at <a href=\"https://user.example/\" rel=\"nofollow noopener\">my site</a></p>"
   :fields   [{:name "Website" :value "<a href=\"https://user.example/\" rel=\"me nofollow noopener\">user.example</a>"}]})

(def site-page
  "The page of the user at https://user.example/."
  "<a rel=me href=https://github.com/ann>GitHub</a> <a rel=me href=https://social.example/@ann>Mastodon</a>")

(defn- world
  "A network with the user's site at https://user.example/, GitHub, and a
  Mastodon server at https://social.example, by `m`: the :page of the
  site, the :github-accounts and :mastodon-accounts by username, the
  :mastodon-opts of the server, and more :routes. It gives a map of the
  :send, the atoms of the :github and the :mastodon server, and the :opts
  of a client."
  [m]
  (let [{:keys [page github-accounts mastodon-accounts mastodon-opts routes]}
        (merge {:page              site-page
                :github-accounts   {"Ann" ann-at-github}
                :mastodon-accounts {"ann" ann-at-mastodon}
                :mastodon-opts     {:profile-scope? true}}
               m)
        [github-routes github]     (t/github {"gh-id" "gh-secret"} github-accounts)
        [mastodon-routes mastodon] (t/mastodon "https://social.example" mastodon-accounts mastodon-opts)
        send                       (t/network (merge github-routes
                                                     mastodon-routes
                                                     {"https://user.example/" (t/page page)}
                                                     routes))]
    {:send     send
     :github   github
     :mastodon mastodon
     :opts     {:send         send
                :redirect-uri "https://app.example/callback"
                :github       {:client-id "gh-id" :client-secret (secret/hide "gh-secret")}
                :mastodon     {:registrations (relmeauth/memory-store)}}}))

(defn- account-of
  "The account of `provider` in the `discovery`."
  [provider {:keys [accounts] :as discovery}]
  (first (filter #(= provider (:provider %)) accounts)))

(defn- request!
  "The authorization request for the account of `provider` in the `world`,
  by its options and `more`, with the :discovery."
  [{:keys [opts] :as world} provider more]
  (let [opts (merge opts more)]
    (async/then (relmeauth/discover! "user.example" opts)
                (fn [discovery]
                  (async/then (relmeauth/authorization-request! discovery (account-of provider discovery) opts)
                              #(assoc % :discovery discovery))))))

(defn- sign-in!
  "Sign the user of https://user.example/ in with the account of `provider`
  in the `world`, by its options and `more`, and give what redeem! gives."
  ([world provider]
   (sign-in! world provider {}))
  ([{:keys [send opts] :as world} provider more]
   (async/then (request! world provider more)
               (fn [{:keys [url session error] :as request}]
                 (if error
                   request
                   (async/then (t/authorize! send url)
                               #(relmeauth/redeem! session % (merge opts more))))))))

(defn- error-type
  "The :type of the :error of `m`."
  [m]
  (get-in m [:error :type]))

(deftest discovery
  (let [{:keys [opts]} (world {:routes {"https://moved.example/"      (t/redirect 301 "https://user.example/")
                                        "https://user.example/gone"  (fn [_] {:status 404 :headers {} :body ""})
                                        "https://social.example/@ann" (t/page "<a rel=me href=https://github.com/ann>")}})]
    (run #(async/then (relmeauth/discover! "user.example" opts)
                      (fn [{:keys [me urls accounts]}]
                        (is (= "https://user.example/" me))
                        (is (= ["https://user.example/"] urls))
                        (is (= ["https://github.com/ann" "https://social.example/@ann"] (map :url accounts)))))
         #(async/then (relmeauth/discover! "moved.example" opts)
                      (fn [{:keys [me urls]}]
                        (is (= "https://moved.example/" me) "the URL that the user gave")
                        (is (= ["https://moved.example/" "https://user.example/"] urls) "with those it went through")))
         #(async/then (relmeauth/discover! "https://user.example/gone" opts)
                      (fn [r] (is (= ::relmeauth/failed (error-type r)))))
         #(async/then (relmeauth/discover! "https://user.example:8443/" opts)
                      (fn [r] (is (= ::relmeauth/invalid-url (error-type r)))))
         #(async/then (relmeauth/discover! "https://social.example/@ann" opts)
                      (fn [r] (is (= ::relmeauth/silo-url (error-type r)) "an account at a provider isn't the user's own")))
         #(async/then (relmeauth/discover! "github.com/ann" opts)
                      (fn [r] (is (= ::relmeauth/silo-url (error-type r)))))
         #(async/then (relmeauth/discover! "https://social.example/@ann" (assoc opts :silo-urls? true))
                      (fn [{:keys [me accounts]}]
                        (is (= "https://social.example/@ann" me) "unless :silo-urls? is true")
                        (is (= ["https://github.com/ann"] (map :url accounts))))))))

(deftest link-backs
  (let [session {:me      "https://user.example/"
                 :urls    ["https://user.example/" "https://www.user.example/"]
                 :account {:provider :github :username "ann" :url "https://github.com/ann"}}
        mastodon (assoc session :account {:provider :mastodon :instance "https://social.example" :username "ann"})]
    (testing "GitHub's website field, in canonical form"
      (is (nil? (relmeauth/account-problem session ann-at-github)) "and the username in any case")
      (is (nil? (relmeauth/account-problem session (assoc ann-at-github :blog "https://User.Example"))))
      (is (nil? (relmeauth/account-problem session (assoc ann-at-github :blog "www.user.example"))) "a URL discovery went through"))
    (testing "a slash at the end of a path, unless :trim-slash? is false"
      (let [ann (assoc session :me "https://user.example/ann/" :urls ["https://user.example/ann/"])]
        (is (nil? (relmeauth/account-problem ann (assoc ann-at-github :blog "user.example/ann"))))
        (is (nil? (relmeauth/account-problem ann (assoc ann-at-github :blog "user.example/ann/"))))
        (is (= ::relmeauth/no-link-back
               (:type (relmeauth/account-problem ann (assoc ann-at-github :blog "user.example/ann") {:trim-slash? false}))))
        (is (= ::relmeauth/no-link-back
               (:type (relmeauth/account-problem ann (assoc ann-at-github :blog "user.example/ann/x")))))))
    (testing "no link back"
      (doseq [blog ["" nil "https://elsewhere.example/" "http://user.example/" "https://user.example/blog"]]
        (is (= ::relmeauth/no-link-back (:type (relmeauth/account-problem session (assoc ann-at-github :blog blog)))) (pr-str blog))))
    (testing "another account than the one that the site names"
      (is (= ::relmeauth/wrong-account (:type (relmeauth/account-problem session (assoc ann-at-github :login "bob")))))
      (is (= ::relmeauth/wrong-account (:type (relmeauth/account-problem session {})))))
    (testing "a link in a Mastodon bio or a profile field"
      (is (nil? (relmeauth/account-problem mastodon ann-at-mastodon)))
      (is (nil? (relmeauth/account-problem mastodon (dissoc ann-at-mastodon :fields))))
      (is (nil? (relmeauth/account-problem mastodon (dissoc ann-at-mastodon :note))))
      (is (= ::relmeauth/no-link-back
             (:type (relmeauth/account-problem mastodon (assoc ann-at-mastodon :note "<p>user.example</p>" :fields [])))))
      (is (= ::relmeauth/wrong-account
             (:type (relmeauth/account-problem mastodon (assoc ann-at-mastodon :username "bob"))))))))

(deftest callbacks
  (let [session {:state "abc"}]
    (is (nil? (relmeauth/callback-problem session {"state" "abc" "code" "x"})))
    (is (nil? (relmeauth/callback-problem session {:state "abc" :code "x"})) "with keywords as keys")
    (is (= ::relmeauth/state-mismatch (:type (relmeauth/callback-problem session {"state" "abd" "code" "x"}))))
    (is (= ::relmeauth/state-mismatch (:type (relmeauth/callback-problem session {"code" "x"}))))
    (is (= {:type ::relmeauth/authorization-error :code "access_denied" :reason "The user said no"}
           (relmeauth/callback-problem session {"state" "abc" "error" "access_denied" "error_description" "The user said no"})))
    (is (= ::relmeauth/no-code (:type (relmeauth/callback-problem session {"state" "abc"}))))))

(def ann-signed-in
  {:me "https://user.example/" :account {:provider :github :username "ann" :url "https://github.com/ann"}})

(deftest signing-in-with-github
  (let [w      (world {})
        denied (world {})
        bob    (world {:github-accounts {"Ann" ann-at-github "bob" {:login "bob" :blog "https://user.example/"}}})
        away   (world {:github-accounts {"Ann" (dissoc ann-at-github :blog)}})]
    (swap! (:github denied) assoc :deny? true)
    (swap! (:github bob) assoc :signed-in "bob")
    (run #(async/then (sign-in! w :github) (fn [r] (is (= ann-signed-in r))))
         #(async/then (request! w :github {})
                      (fn [{:keys [url session]}]
                        (is (str/starts-with? url "https://github.com/login/oauth/authorize?"))
                        (is (= {"login" "ann" "allow_signup" "false" "code_challenge_method" "S256"}
                               (select-keys (t/query url) ["login" "allow_signup" "code_challenge_method"])))
                        (is (not (contains? (t/query url) "scope")) "no scope, for public information alone")
                        (-> (t/authorize! (:send w) url)
                            (async/then (fn [params]
                                          (async/then (relmeauth/redeem! session params (:opts w))
                                                      (fn [r]
                                                        (is (= ann-signed-in r))
                                                        (relmeauth/redeem! session params (:opts w))))))
                            (async/then (fn [r]
                                          (is (= ::relmeauth/token-error (error-type r)) "a code works once"))))))
         #(async/then (request! w :github {})
                      (fn [{:keys [url session]}]
                        (async/then (t/authorize! (:send w) url)
                                    (fn [params]
                                      (async/then (relmeauth/redeem! (assoc session :code-verifier (relmeauth/token)) params (:opts w))
                                                  (fn [r]
                                                    (testing "PKCE, and GitHub's error with 200"
                                                      (is (= ::relmeauth/token-error (error-type r)))
                                                      (is (= "invalid_grant" (get-in r [:error :code]))))))))))
         #(async/then (sign-in! w :github {:github {:client-id "gh-id" :client-secret "wrong"}})
                      (fn [r] (is (= "invalid_client" (get-in r [:error :code])) (pr-str r))))
         #(async/then (sign-in! denied :github)
                      (fn [r]
                        (is (= ::relmeauth/authorization-error (error-type r)))
                        (is (= "access_denied" (get-in r [:error :code])))))
         #(async/then (sign-in! bob :github)
                      (fn [r] (is (= ::relmeauth/wrong-account (error-type r)) "the site names Ann, not Bob")))
         #(async/then (sign-in! away :github)
                      (fn [r] (is (= ::relmeauth/no-link-back (error-type r))))))))

(deftest signing-in-with-mastodon
  (let [w       (world {})
        older   (world {:mastodon-opts {}})
        refused (world {:mastodon-opts {:refuse? true}})
        bob     (world {:mastodon-accounts {"ann" ann-at-mastodon "bob" (assoc ann-at-mastodon :username "bob")}})
        a       (atom {})
        stored  (assoc-in (:opts w) [:mastodon :registrations] (relmeauth/memory-store a))
        apps    #(count (:apps @(:mastodon %)))]
    (swap! (:mastodon bob) assoc :signed-in "bob")
    (run #(async/then (sign-in! w :mastodon)
                      (fn [r]
                        (is (= {:me      "https://user.example/"
                                :account {:provider :mastodon :instance "https://social.example" :username "ann"
                                          :url      "https://social.example/@ann"}}
                               r))))
         #(async/then (sign-in! w :mastodon)
                      (fn [r]
                        (is (:me r))
                        (is (= 1 (apps w)) "the app registers once")))
         #(async/then (request! w :mastodon {})
                      (fn [{:keys [url]}]
                        (is (str/starts-with? url "https://social.example/oauth/authorize?"))
                        (is (= "profile" (get (t/query url) "scope")) "the scope of Mastodon 4.3, which reads the account alone")))
         #(async/then (request! older :mastodon {})
                      (fn [{:keys [url]}]
                        (is (= "read:accounts" (get (t/query url) "scope")) "on an older server")))
         #(async/then (sign-in! older :mastodon) (fn [r] (is (:me r))))
         #(async/then (sign-in! refused :mastodon)
                      (fn [r]
                        (is (= ::relmeauth/registration-error (error-type r)))
                        (is (= "https://social.example" (get-in r [:error :instance])))))
         #(async/then (sign-in! bob :mastodon) (fn [r] (is (= ::relmeauth/wrong-account (error-type r)))))
         (fn []
           (testing "a registration in a store of your own"
             (async/then (sign-in! w :mastodon {:mastodon (:mastodon stored)})
                         (fn [r]
                           (is (:me r))
                           (is (= 2 (apps w)))
                           (let [registration (get @a "https://social.example")]
                             (is (secret/hidden? (:client-secret registration)) "with its secret hidden")
                             (is (not (str/includes? (pr-str @a) (secret/reveal (:client-secret registration)))))
                             (swap! a update "https://social.example" update :client-secret secret/reveal)
                             (is (= "profile" (:scope registration)))
                             (is (= "https://app.example/callback" (:redirect-uri registration))))))))
         #(async/then (sign-in! w :mastodon {:mastodon (:mastodon stored)})
                      (fn [r]
                        (is (:me r) "a secret that the store gives as plain text")
                        (is (= 2 (apps w)))))
         #(async/then (sign-in! w :mastodon {:mastodon (:mastodon stored) :redirect-uri "https://app.example/other"})
                      (fn [r]
                        (is (:me r))
                        (is (= 3 (apps w)) "a new registration for another redirect URL")))
         #(async/then (request! w :mastodon {})
                      (fn [{:keys [url session]}]
                        (async/then (t/authorize! (:send w) url)
                                    (fn [params]
                                      (async/then (relmeauth/redeem! session params (assoc-in (:opts w) [:mastodon :registrations]
                                                                                              (relmeauth/memory-store)))
                                                  (fn [r] (is (= ::relmeauth/not-registered (error-type r))))))))))))

(def secret-text "a secret of thirty-two bytes, at least")

(defn- seconds-later
  "The instant `n` seconds from now."
  [n]
  #?(:clj  (java.util.Date. (+ (System/currentTimeMillis) (* 1000 n)))
     :cljs (js/Date. (+ (js/Date.now) (* 1000 n)))))

(deftest signed-states
  (let [w    (world {})
        more {:secret secret-text :data {:page "/posts/1"}}]
    (run #(async/then (request! w :github more)
                      (fn [{:keys [url session]}]
                        (let [state (get (t/query url) "state")
                              nonce (:nonce session)]
                          (is (= state (:state session)))
                          (testing "the session comes back from the state and the nonce"
                            (is (= session (relmeauth/state-session secret-text state nonce)))
                            (is (= {:page "/posts/1"} (:data (relmeauth/state-session secret-text state nonce)))))
                          (testing "nil for"
                            (is (nil? (relmeauth/state-session secret-text state (relmeauth/token))) "another browser's nonce")
                            (is (nil? (relmeauth/state-session secret-text state nil)) "no nonce")
                            (is (nil? (relmeauth/state-session secret-text (str state "x") nonce)) "a changed state")
                            (is (nil? (relmeauth/state-session (str secret-text "!") state nonce)) "another secret")
                            (is (nil? (relmeauth/state-session secret-text state nonce
                                                               {:now-fn (fn [] (seconds-later 601))}))
                                "an old one"))
                          (-> (t/authorize! (:send w) url)
                              (async/then (fn [params]
                                            (relmeauth/redeem! (relmeauth/state-session secret-text (get params "state") nonce)
                                                               params
                                                               (merge (:opts w) more))))
                              (async/then (fn [r] (is (= ann-signed-in r)))))))))))

(deftest requests-that-throw
  (let [{:keys [opts]} (world {})
        discovery      {:me "https://user.example/" :urls ["https://user.example/"]}
        github         {:provider :github :username "ann" :url "https://github.com/ann"}
        mastodon       {:provider :mastodon :instance "https://social.example" :username "ann"}]
    (is (thrown? #?(:clj Exception :cljs :default) (relmeauth/authorization-request! discovery github (dissoc opts :redirect-uri))))
    (is (thrown? #?(:clj Exception :cljs :default) (relmeauth/authorization-request! discovery github (dissoc opts :github))))
    (is (thrown? #?(:clj Exception :cljs :default) (relmeauth/authorization-request! discovery mastodon (dissoc opts :mastodon))))
    (is (thrown? #?(:clj Exception :cljs :default) (relmeauth/authorization-request! discovery {:provider :twitter} opts)))))
