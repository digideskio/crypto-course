(ns crypto-course.algebra)

(defn gcd
  "Returns the greatest common divisor of a and b."
  [a b]
  (if (zero? b)
    a
    (gcd b (mod a b))))

(defn extended-gcd
  "Returns [g c d] such that g = a*c + b*d and g is the greatest common divisor
  of a and b."
  [a b]
  (if (zero? a)
    [b 0 1]
    (let [[g y x] (extended-gcd (mod b a) a)]
      [g (- x (* (quot b a) y)) y])))

(defn mult-inverse
  "Takes m and returns a function that returns the multiplicative inverse of
  its argument modulo m.
  
  Example:
  (let [inverser (mult-inverse 26)]
    (inverser 17))
  23"
  [m]
  (fn [a]
    (let [[g x y] (extended-gcd a m)]
      (if (not= g 1)
        nil ; No multiplicative inverse exists.
        (mod x m)))))