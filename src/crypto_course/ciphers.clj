(ns crypto-course.ciphers
  (:require [crypto-course.algebra :as alg]
            [crypto-course.utils :as utils]))

(defprotocol Cryptosystem
  "Defines a cryptosystem by the ability to encrypt plain-text and decrypt
  cipher-text. It should be the case that (decrypt (encrypt plain-text)) return
  the original plain-text.
  
  Any notion of keys is left as an implementation detail."
  (encrypt [this plain-text]
    "Encrypts plain-text using whatever key is used by the cryptosystem. The
    input should be in the set of legal plain-text and the output in the set of
    legal cipher-text.")
  (decrypt [this cipher-text]
    "Decrypts cipher-text using whatever key is used by the cryptosystem. The
    input should be in the set of legal cipher-text and the output in the set
    of legal plain-text."))

;;;; Cryptosystem 1.1: Shift Cipher

(deftype ShiftCipher
  [k]
  Cryptosystem
    (encrypt [this plain-text]
      (mod (+ plain-text k) 26))
    (decrypt [this cipher-text]
      (mod (- cipher-text k) 26)))

(defn shift-cipher
  "The Shift Cipher encrypts by shifting the plain-text k letters forwards in
  the alphabet.
  
  Takes an integer k as key such that 0 <= k <= 25
  
  Plain-text and cipher-text are both Z26 integers."
  [k]
  {:pre [(<= 0 k 25)]}
  (ShiftCipher. k))

;;;; Cryptosystem 1.2: Substitution Cipher

(deftype SubstitutionCipher
  [perm]
  Cryptosystem
    (encrypt [this plain-text]
      (perm plain-text))
    (decrypt [this cipher-text]
      ((apply hash-map (interleave (vals perm) (keys perm))) cipher-text)))

(defn substitution-cipher
  "The Substitution Cipher encrypts by substituting each letter with another
  letter using a permutation of the letters.
  
  Takes a permutation of [0 1 ... 25] as key.
  
  Plain-text and cipher-text are both Z26 integers."
  [perm]
  {:pre [(= (sort perm) (range 26))]}
  (SubstitutionCipher. (apply hash-map (interleave (range 26) perm))))

;;;; Cryptosystem 1.3: Affine Cipher 

(deftype AffineCipher
  [a b]
  Cryptosystem
   	(encrypt [this plain-text]
      (mod (+ (* a plain-text) b) 26))
    (decrypt [this cipher-text]
      (mod (* ((alg/mult-inverse 26) a) (- cipher-text b)) 26)))

(defn affine-cipher
  "Returns an Affine Cipher which encrypts using an affine function of the form
  
  e(x) = (ax + b) mod 26
  
  for a and b in Z26, such that gcd(a, 26) = 1."
  [a b]
  {:pre [(= 1 (alg/gcd a 26))
         (<= 0 a 25)]}
  (AffineCipher. a b))