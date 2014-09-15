(ns crypto-course.ciphers
  (:require [crypto-course.algebra :as alg]
            [crypto-course.utils :as utils]))

;;;; Define what a cryptosystem (in Clojure) must satisfy.

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

;;;; Define several handy helper functions.

(defn- z26
  "Performs the operation and reduces the result modulo 26."
  [f & args]
  (mod (apply f args) 26))

(defn- z26?
  "Returns true if k is an integer in the inclusive range [0 25] and false
  otherwise."
  [k]
  (<= 0 k 25))

;;;; Cryptosystem 1.1: Shift Cipher

(deftype ShiftCipher
  [k]
  Cryptosystem
    (encrypt [this plain-text]
      (z26 + plain-text k))
    (decrypt [this cipher-text]
      (z26 - cipher-text k)))

(defn shift-cipher
  "The Shift Cipher encrypts by shifting the plain-text k letters forwards in
  the alphabet.
  
  Takes an integer k as key such that 0 <= k <= 25
  
  Plain-text and cipher-text are both Z26 integers."
  [k]
  {:pre [(z26? k)]}
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
      (z26 + (* a plain-text) b))
    (decrypt [this cipher-text]
      (z26 * ((alg/mult-inverse 26) a) (- cipher-text b))))

(defn affine-cipher
  "Returns an Affine Cipher which encrypts using an affine function of the form
  
  e(x) = (ax + b) mod 26
  
  for a and b in Z26, such that gcd(a, 26) = 1."
  [a b]
  {:pre [(= 1 (alg/gcd a 26))
         (z26? a)
         (z26? b)]}
  (AffineCipher. a b))

;;;; Cryptosystem 1.4: Vigenére Cipher

(deftype VigenereCipher
  [k]
  Cryptosystem
    (encrypt [this plain-text]
      (map #(z26 + %1 %2) plain-text k))
    (decrypt [this cipher-text]
      (map #(z26 - %1 %2) cipher-text k)))

(defn vigenere-cipher
  "Returns a Vigénere Cipher which encrypts the i'th plain-text under the i'th
  key much like the Shift Cipher:
  
  e(x_i) = (x_i + k_(i mod 26))
  
  The key is a sequence of elements in Z26 and will repeat itself if the
  plain-text is longer than the key."
  [k]
  {:pre [(sequential? k)
         (every? z26? k)]}
  (VigenereCipher. (cycle k)))

;;;; Cryptosystem 1.6: Permutation Cipher

(defn- permute
  [indexable perm]
  (map (partial get indexable) perm))

(defn- indexable-partition
  [n s]
  (map vec (partition n s)))

(defn- permute-parts
  [parts perm]
  (apply concat (map permute parts (repeat perm))))

(deftype PermutationCipher
  [perm]
  Cryptosystem
    (encrypt [this plain-text]
      (let [parts (indexable-partition (count perm) plain-text)]
        (permute-parts parts perm)))
    (decrypt [this cipher-text]
      (let [parts (indexable-partition (count perm) cipher-text)
            reverse-perm (map #(.indexOf perm %) (range (count perm)))]
        (permute-parts parts reverse-perm))))

(defn permutation-cipher
  [perm]
  {:pre [(= (sort perm) (range (count perm)))
         (every? z26? perm)]}
  (PermutationCipher. perm))