; eps(p) = min(E, rho + 2*sqrt(rho*L)) when nothing Gaussian was released, with
; L = ln(1/delta) > 0; s = sqrt(rho*L). Adding a release (dE >= 0, dRho >= 0)
; never decreases it.
(declare-const E Real)(declare-const rho Real)(declare-const s Real)(declare-const L Real)
(declare-const dE Real)(declare-const dRho Real)(declare-const s2 Real)
(assert (and (>= E 0) (>= rho 0) (> L 0) (>= dE 0) (>= dRho 0)))
(assert (and (>= s 0) (= (* s s) (* rho L))))
(assert (and (>= s2 0) (= (* s2 s2) (* (+ rho dRho) L))))
(define-fun m ((x Real) (y Real)) Real (ite (<= x y) x y))
(assert (< (m (+ E dE) (+ rho dRho (* 2 s2))) (m E (+ rho (* 2 s)))))
(check-sat)
