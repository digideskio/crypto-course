(ns crypto-course.utils)

;;;; Private transducers to help transform various sequences.

(def ^:private to-char (map char))
(def ^:private to-int (map int))
(def ^:private add-offset-to-a (map #(+ % (int \a))))
(def ^:private sub-offset-to-a (map #(- % (int \a))))
(def ^:private filter-a-to-z (filter #(< -1 % 26)))

;;;; Composite transducers.

(def ^:private z26-transducer
  (comp to-int sub-offset-to-a filter-a-to-z))

(def ^:private reverse-z26-transducer
  (comp filter-a-to-z add-offset-to-a to-char))

(defn string->z26
  "Transforms a string into a sequence of Z26 integers under the following
  interpretation:
  
  a -> 0, b -> 1, ..., z -> 25
  
  Any character outside the inclusive range [a-z] is discarded."
  [string]
  (sequence z26-transducer (seq string)))

(defn z26->string
  "Transforms a sequence of Z26 integers into a string under the following
  interpretation:
  
  0 -> a, 1 -> b, ..., 25 -> z
  
  Any integer outside the inclusive range [0-25] is discarded."
  [z26]
  (apply str (sequence reverse-z26-transducer z26)))