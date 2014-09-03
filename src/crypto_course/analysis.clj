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