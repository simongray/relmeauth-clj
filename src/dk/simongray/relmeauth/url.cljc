(ns dk.simongray.relmeauth.url
  "The URLs of users: those that a user can sign in as, and the canonical
  form in which they're compared.

  The rules are IndieAuth's, so that a user signs in as the same URL here
  as at an IndieAuth server. This is a copy of indieauth-clj's (see
  doc/sibling-notes.md)."
  (:require [clojure.string :as str]
            [dk.simongray.wary-fetch.url :as url]))

;; RFC 3986, appendix B
(defn ^:no-doc parts
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
  (let [{:keys [scheme authority path fragment]} (parts s)
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
        {:keys [scheme authority path query fragment]} (parts s)
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

(defn trim-slash
  "The canonical `url` without a slash at the end of its path, unless the
  path is /.

      (trim-slash \"https://example.com/me/\") ;; => \"https://example.com/me\""
  [url]
  (str/replace url #"^(https?://[^/?#]*/[^?#]*[^/?#])/(?=[?#]|$)" "$1"))
