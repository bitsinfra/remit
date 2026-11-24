; x in [min,max], p > 0; the emitted index is round((x-min)/p) clamped to the
; last representable step, i.e. an integer k with 0 <= k and min + k*p <= max.
; Claim: k is one of floor((max-min)/p)+1 values.
(declare-const lo Real)(declare-const hi Real)(declare-const p Real)(declare-const k Int)
(assert (> p 0.0))(assert (<= lo hi))
(assert (>= k 0))(assert (<= (+ lo (* (to_real k) p)) hi))
(assert (not (and (>= k 0) (<= k (to_int (/ (- hi lo) p))))))
(check-sat)
