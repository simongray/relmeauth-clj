(ns ^:no-doc dk.simongray.relmeauth.json
  "JSON on both platforms, with data.json on the JVM and the JSON of
  JavaScript. An object reads as a map with keyword keys, in the names
  that GitHub and Mastodon give them.

  This is a copy of indieauth-clj's json.cljc, until wary-fetch reads JSON
  (see doc/sibling-notes.md)."
  #?(:clj (:require [clojure.data.json :as json])))

(defn read-json
  "The value of the JSON text `s`, or nil when `s` isn't JSON."
  [s]
  (when (string? s)
    (try
      #?(:clj  (json/read-str s :key-fn keyword)
         :cljs (js->clj (js/JSON.parse s) :keywordize-keys true))
      (catch #?(:clj Exception :cljs :default) _
        nil)
      ;; JSON nested deep enough to use up the stack
      #?(:clj (catch StackOverflowError _
                nil)))))

(defn read-object
  "The map of the JSON object in the text `s`, or nil when `s` holds
  another value or isn't JSON."
  [s]
  (let [x (read-json s)]
    (when (map? x)
      x)))

(defn write-json
  "The JSON text of the value `x`, with keywords as their names."
  [x]
  #?(:clj  (json/write-str x :escape-slash false :escape-unicode false)
     :cljs (js/JSON.stringify (clj->js x))))
