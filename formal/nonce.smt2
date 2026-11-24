; An envelope is admitted at t only if t < exp, and its nonce entry is kept until
; exp + skew with skew >= 0. Two admissions t1 < t2 of the same nonce would need
; the entry to be gone at t2 while t2 < exp.
(declare-const t1 Int)(declare-const t2 Int)(declare-const exp Int)(declare-const skew Int)
(assert (>= skew 0))(assert (< t1 t2))(assert (< t1 exp))(assert (< t2 exp))
(assert (not (> (+ exp skew) t2))) ; entry expired at t2
(check-sat)
