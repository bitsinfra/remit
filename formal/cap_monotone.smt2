; Narrowing [min,max] or coarsening the granularity never increases the count.
(declare-const lo Int)(declare-const hi Int)(declare-const lo2 Int)(declare-const hi2 Int)
(declare-const g Int)(declare-const q Int)(declare-const q2 Int)(declare-const r Int)(declare-const r2 Int)
(assert (> g 0))(assert (<= lo lo2))(assert (<= lo2 hi2))(assert (<= hi2 hi))
; q = (hi-lo) div g, q2 = (hi2-lo2) div g
(assert (= (- hi lo) (+ (* g q) r)))(assert (and (>= r 0) (< r g)))
(assert (= (- hi2 lo2) (+ (* g q2) r2)))(assert (and (>= r2 0) (< r2 g)))
(assert (> q2 q))
(check-sat)
