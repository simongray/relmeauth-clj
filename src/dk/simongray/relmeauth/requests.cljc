(ns ^:no-doc dk.simongray.relmeauth.requests
  "The requests to the user's site and to the providers, and their
  answers. A request that fails gives a map of the :error, with its :type
  and :reason, rather than throwing, and and-then passes it on."
  (:require [dk.simongray.relmeauth :as-alias relmeauth]
            [dk.simongray.wary-fetch :as http]
            [dk.simongray.wary-fetch.async :as async]
            [dk.simongray.wary-fetch.json :as json]))

(defn failure
  "A map of the :error of `type`, a keyword, with the `reason` and the facts
  of the map `m`."
  ([type reason]
   (failure type reason {}))
  ([type reason m]
   {:error (merge {:type type :reason reason} m)}))

(defn and-then
  "The result of `f` on the value of `x`, once it has one, unless it's a
  map of the :error, which stays as it is."
  [x f]
  (async/then x (fn [m] (if (:error m) m (f m)))))

(defn fetch!
  "The response to a GET of `url` for the media types `accept`, with a body
  of `max-bytes` at most, by `opts`, or a map of the :error."
  [url accept max-bytes opts]
  (async/then (async/attempt
               #(http/fetch! url (assoc opts :accept accept :max-bytes max-bytes)))
              (fn [{:keys [value error]}]
                (cond
                  error
                  {:error (http/failure error)}

                  (not (<= 200 (:status value) 299))
                  (failure ::relmeauth/failed (str url " answered " (:status value))
                           {:url url :status (:status value)})

                  :else
                  value))))

(defn exchange!
  "The response to the `request`, sent by `opts` without following a
  redirect, or a map of the :error."
  [request {:keys [send max-json-bytes] :as opts}]
  (async/then (http/try-send! send request (assoc opts
                                                  :max-bytes max-json-bytes
                                                  :max-redirects 0))
              (fn [{:keys [value error]}]
                (or value {:error (http/failure error)}))))

(defn form-request
  "The request that posts the form of `fields`, pairs of a name and a
  value, to `url` for a JSON answer, with its body hidden."
  [url fields]
  (http/form-request url fields {:headers {"Accept" "application/json"}}))

;; RFC 6749, section 5.2. GitHub answers an error with 200 too.
(defn json-answer
  "The map of the JSON object in the `response`, if its status is a
  success and it holds no error, or a map of the :error of `type`, with
  the :code of the error that the provider gave."
  [type {:keys [status body] :as response}]
  (let [x                                 (json/read-json body)
        m                                 (when (map? x) x)
        {:keys [error error_description]} m
        success?                          (and (integer? status)
                                               (<= 200 status 299))]
    (cond
      (and success? m (nil? error))
      m

      (and success? (nil? m))
      (failure type "The provider's answer isn't a JSON object"
               {:status status})

      :else
      (failure type (if (string? error_description)
                      error_description
                      (str "The provider answered "
                           (if (string? error) error status)))
               (cond-> {:status status}
                 (string? error) (assoc :code error))))))
