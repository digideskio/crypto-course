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

(defn swap
  "Returns vector v with index i1 and i2 swapped."
  [v [i1 i2]]
  (assoc v i2 (v i1) i1 (v i2)))

(defn gen-shuffle
  "Generates a shuffled vector. Swaps two indexes in the vector for each step."
  [v]
  (let [r (gen/choose 0 (dec (count v)))]
    (gen/fmap (partial reduce swap v)
      (gen/vector (gen/tuple r r)))))

(def z26-gen
  "Generates a natural number in the inclusive range [0 25]."
  (gen/elements (range 26)))

(def z26-star-gen
  "Generates a natural number in the inclusive range [0 25] which is co-prime
  to 26."
  (gen/elements (filter #(= 1 (alg/gcd % 26)) (range 26))))

(def z26-perm-gen
  "Generates a random permutation of the inclusive range [0 25]."
  (gen-shuffle
    (vec (range 26))))

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

;;; Substitution Cipher

(def prop-substitution-cipher
  "States for any fixed key and plain-text, it should be the case that the
  decryption of the encryption equals the plain-text."
  (prop/for-all [perm z26-perm-gen
                 plain-text z26-gen]
                (let [cipher (ciphers/substitution-cipher perm)
                      encryp (ciphers/encrypt cipher plain-text)
                      decryp (ciphers/decrypt cipher encryp)]
                  (= plain-text decryp))))

(expect (->SimpleCheck) (tc/quick-check 100 prop-substitution-cipher))

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