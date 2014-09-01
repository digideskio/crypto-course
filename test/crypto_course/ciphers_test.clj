(ns crypto-course.ciphers-test
  (:require [crypto-course.ciphers :as ciphers]
            [crypto-course.algebra :as alg]
            [clojure.test.check :as tc]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [expectations :refer :all]))

;;;; Expectations CustomPred for better integration.

(defrecord SimpleCheck []
  CustomPred
    (expect-fn [e a]
      (true? (:result a)))
    (expected-message [e a str-e str-a]
      (format "%s of %s failures" (:failing-size a) (:num-tests a)))
    (actual-message [e a str-e str-a]
      (format "fail: %s" (:fail a)))
    (message [e a str-e str-a]
      (format "shrunk: %s" (get-in a [:shrunk :smallest]))))

;;;; Generators.

(def z26-gen
  "Generates a natural number in the inclusive range [0 25]."
  (gen/fmap #(mod % 26) gen/nat))

(def z26-star-gen
  "Generates a natural number in the inclusive range [0 25] which is co-prime
  to 26."
  (gen/such-that #(= 1 (alg/gcd % 26)) z26-gen))

;;;; Properties.

;;; Shift Cipher

(def prop-shift-cipher
  "States for any fixed key and plain-text, it should be the case that the
  decryption of the encryption equals the plain-text."
  (prop/for-all [cipher-key z26-gen
                 plain-text z26-gen]
                (let [cipher (ciphers/shift-cipher cipher-key)
                      encryp (ciphers/encrypt cipher plain-text)
                      decryp (ciphers/decrypt cipher encryp)]
                  (= plain-text decryp))))

(expect (->SimpleCheck) (tc/quick-check 100 prop-shift-cipher))

;;; Affine Cipher

(def prop-affine-cipher
  "States for any fixed key and plain-text, it should be the case that the
  decryption of the encryption equals the plain-text."
  (prop/for-all [key-a z26-star-gen
                 key-b z26-gen
                 plain-text z26-gen]
                (let [cipher (ciphers/affine-cipher key-a key-b)
                      encryp (ciphers/encrypt cipher plain-text)
                      decryp (ciphers/decrypt cipher encryp)]
                  (= plain-text decryp))))

(expect (->SimpleCheck) (tc/quick-check 100 prop-affine-cipher))