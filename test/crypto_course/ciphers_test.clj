(ns crypto-course.ciphers-test
  (:require [crypto-course.ciphers :as ciphers]
    		[clojure.test.check :as tc]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [expectations :refer :all]))

;;;; Generators.

(def z26-gen
  "Generates a natural number in the inclusive range [0 25]."
  (gen/fmap #(mod % 26) gen/nat))

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

(expect {:result true} (in (tc/quick-check 100 prop-shift-cipher)))