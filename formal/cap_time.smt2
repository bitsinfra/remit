; A timestamp on the grid min + k*g within [min,max] has index <= (max-min) div g.
(declare-const lo Int)(declare-const hi Int)(declare-const g Int)(declare-const k Int)
(assert (> g 0))(assert (<= lo hi))(assert (>= k 0))(assert (<= (+ lo (* k g)) hi))
(assert (not (<= k (div (- hi lo) g))))
(check-sat)
