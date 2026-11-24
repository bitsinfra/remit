; State: spent (including open reservations), open = worst case held, cap.
; Inductive invariant: 0 <= open <= spent <= cap. Transitions: reserve(a) guarded
; by spent + a <= cap; settle(a, used) with 0 <= used <= a refunds a - used; crash
; keeps open reservations charged (open' = 0, spent' = spent).
(declare-const cap Int)(declare-const spent Int)(declare-const open Int)(declare-const a Int)(declare-const used Int)
(define-fun inv ((s Int) (o Int)) Bool (and (<= 0 o) (<= o s) (<= s cap)))
(assert (inv spent open))(assert (>= a 0))
(assert (not (and
  (=> (<= (+ spent a) cap) (inv (+ spent a) (+ open a)))
  (=> (and (<= a open) (<= 0 used) (<= used a)) (inv (- spent (- a used)) (- open a)))
  (inv spent 0))))
(check-sat)
