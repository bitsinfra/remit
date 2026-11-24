; |struct| = product of field counts; |optional T| = |T| + 1 <= bound given |T| <= bound.
(declare-const a Int)(declare-const A Int)(declare-const b Int)(declare-const B Int)
(assert (and (>= a 0) (<= a A) (>= b 0) (<= b B)))
(assert (or (> (+ a 1) (+ A 1))
            (and (<= (* a b) (* A b)) (<= (* A b) (* A B)) (> (* a b) (* A B)))))
(check-sat)
