(ns crypto-course.analysis
  (:require [clojure.string :as str]
            [crypto-course.utils :as util]))

(defn sorted-frequencies
  "Returns the frequencies of elements in coll in order of descending
  frequency."
  [coll]
  ((comp reverse (partial sort-by val) frequencies) coll))

(defn repeating-n-grams
  "Find every sequence of length n that appears more than once in coll."
  [n coll]
  (take-while #(> (val %) 1) (sorted-frequencies (partition n 1 coll))))

(defn index-of-coincidence
  "Returns the index of coincidence, which is the probability that two elements
  - picked randomly from a set with frequencies as in freqs - are identical.
  
  The index of coincidence is expected to be ~0.065 for English text and ~0.038
  for completely uniformly distributed letters."
  [freqs]
  (let [occur (vals freqs)
        sum   (reduce + occur)
        xform (map #(* % (dec %)))]
    (/ (transduce xform + 0 occur) (* sum (dec sum)))))
