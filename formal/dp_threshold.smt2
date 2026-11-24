; Per unit u, kept(u) = min(rows(u), m). For any other unit the kept rows do not
; depend on u, so removing u changes the kept total by at most m.
(declare-const m Int)(declare-const ru Int)(declare-const others Int)
(assert (and (>= m 1) (>= ru 0) (>= others 0)))
(define-fun kept ((r Int)) Int (ite (<= r m) r m))
(assert (not (<= (- (+ others (kept ru)) others) m)))
(check-sat)
