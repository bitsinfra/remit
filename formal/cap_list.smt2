; Induction step: S_k = sum_{i<=k} n^i, P_k = n^k, n >= 1.
; Hypothesis S_k <= (k+1) P_k; claim S_{k+1} <= (k+2) P_{k+1}. (Base: S_0 = 1 <= 1.)
(declare-const n Int)(declare-const k Int)(declare-const S Int)(declare-const P Int)
(assert (>= n 1))(assert (>= k 0))(assert (>= P 1))
(assert (<= S (* (+ k 1) P)))
(define-fun P1 () Int (* n P))
(define-fun S1 () Int (+ S P1))
(assert (>= P1 P)) ; n >= 1, P >= 1
(assert (<= (* (+ k 1) P) (* (+ k 1) P1))) ; monotonicity of multiplication by k+1 >= 0
(assert (not (<= S1 (+ (* (+ k 1) P1) P1))))
(check-sat)
