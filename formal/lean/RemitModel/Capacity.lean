/-!
# Capacity soundness

A model of the bounded result types, the emit-plane validator and the capacity
formula. Numbers are integers in some fixed unit, so `Float {min,max,precision}`
is `quant lo hi p` with all three scaled by the same factor.

Main results:
* `normalize_mem`  : whatever the validator releases is one of `vals t`;
* `length_vals_le` : `vals t` has at most `card t` elements, and the Holder
  charges `log2 (card t)` bits;
* `normalize_idem` : normalizing a released value changes nothing.
-/
namespace Remit

inductive Ty where
  | bool
  /-- `lo..hi`, step 1. -/
  | int (lo hi : Int)
  /-- Nearest grid point `lo + k*p`, index clamped to the last step. -/
  | quant (lo hi : Int) (p : Nat)
  /-- Floor onto `lo + k*g` (timestamps, dates). -/
  | grid (lo hi : Int) (g : Nat)
  | enum (n : Nat)
  /-- At most `l` characters from an alphabet of `c`. -/
  | str (l c : Nat)
  | list (m : Nat) (t : Ty)
  | unit
  | pair (a b : Ty)
  | opt (t : Ty)

/-- Values, both as produced by untrusted code and as released. -/
inductive Val where
  | null
  | bool (b : Bool)
  | num (i : Int)
  | sym (n : Nat)
  | str (s : List Nat)
  | arr (xs : List Val)
  | unit
  | pair (a b : Val)

/-- Index of the last grid point. -/
def lastStep (lo hi : Int) (p : Nat) : Int := (hi - lo) / p

/-- Nearest step, halves up, clamped to the last one. -/
def nearest (lo hi : Int) (p : Nat) (x : Int) : Int :=
  min ((2 * (x - lo) + p) / (2 * p)) (lastStep lo hi p)

def mapOpt (f : Val → Option Val) : List Val → Option (List Val)
  | [] => some []
  | x :: xs =>
    match f x, mapOpt f xs with
    | some y, some ys => some (y :: ys)
    | _, _ => none

/-- The emit plane: `none` is `type_violation`. -/
def normalize : Ty → Val → Option Val
  | .bool, .bool b => some (.bool b)
  | .int lo hi, .num x => if lo ≤ x ∧ x ≤ hi then some (.num x) else none
  | .quant lo hi p, .num x =>
    if 0 < p ∧ lo ≤ x ∧ x ≤ hi then some (.num (lo + nearest lo hi p x * p)) else none
  | .grid lo hi g, .num x =>
    if 0 < g ∧ lo ≤ x ∧ x ≤ hi then some (.num (lo + (x - lo) / g * g)) else none
  | .enum n, .sym k => if k < n then some (.sym k) else none
  | .str l c, .str s => if s.length ≤ l ∧ ∀ x ∈ s, x < c then some (.str s) else none
  | .list m t, .arr xs =>
    if xs.length ≤ m then (mapOpt (normalize t) xs).map .arr else none
  | .unit, .unit => some .unit
  | .pair a b, .pair x y =>
    match normalize a x, normalize b y with
    | some x', some y' => some (.pair x' y')
    | _, _ => none
  | .opt _, .null => some .null
  | .opt t, v => normalize t v
  | _, _ => none

/-- `2 ^ capacity`. A type nothing inhabits is charged like a constant. -/
def card : Ty → Nat
  | .bool => 2
  | .int lo hi => max 1 (hi - lo + 1).toNat
  | .quant lo hi p => max 1 (lastStep lo hi p + 1).toNat
  | .grid lo hi g => max 1 (lastStep lo hi g + 1).toNat
  | .enum n => max 1 n
  | .str l c => (l + 1) * (max 1 c) ^ l
  | .list m t => (m + 1) * card t ^ m
  | .unit => 1
  | .pair a b => card a * card b
  | .opt t => card t + 1

/-- All lists over `xs` of length exactly `k`. -/
def tuples {α : Type} (xs : List α) : Nat → List (List α)
  | 0 => [[]]
  | k + 1 => xs.flatMap fun x => (tuples xs k).map (x :: ·)

/-- All lists over `xs` of length at most `m`. -/
def seqs {α : Type} (xs : List α) : Nat → List (List α)
  | 0 => [[]]
  | m + 1 => seqs xs m ++ tuples xs (m + 1)

def steps (lo : Int) (p : Int) (n : Nat) : List Val :=
  (List.range n).map fun (k : Nat) => Val.num (lo + (k : Int) * p)

/-- Every value the Holder can release at a type. -/
def vals : Ty → List Val
  | .bool => [.bool false, .bool true]
  | .int lo hi => steps lo 1 (hi - lo + 1).toNat
  | .quant lo hi p => steps lo p (lastStep lo hi p + 1).toNat
  | .grid lo hi g => steps lo g (lastStep lo hi g + 1).toNat
  | .enum n => (List.range n).map .sym
  | .str l c => (seqs (List.range c) l).map .str
  | .list m t => (seqs (vals t) m).map .arr
  | .unit => [.unit]
  | .pair a b => (vals a).flatMap fun x => (vals b).map (.pair x ·)
  | .opt t => .null :: vals t

/-! ## Counting -/

theorem length_flatMap_const {α β : Type} (f : α → List β) (n : Nat) (xs : List α)
    (h : ∀ x ∈ xs, (f x).length = n) : (xs.flatMap f).length = xs.length * n := by
  induction xs with
  | nil => simp
  | cons x xs ih =>
    rw [List.flatMap_cons, List.length_append, h x (by simp), ih (fun y hy => h y (by simp [hy]))]
    simp [Nat.succ_mul, Nat.add_comm]

theorem length_tuples {α : Type} (xs : List α) (k : Nat) :
    (tuples xs k).length = xs.length ^ k := by
  induction k with
  | zero => simp [tuples]
  | succ k ih =>
    rw [tuples, length_flatMap_const _ (xs.length ^ k) _ (by intro x _; simp [ih])]
    rw [Nat.pow_succ, Nat.mul_comm]

theorem length_seqs_le {α : Type} (xs : List α) (c m : Nat) (hc : 1 ≤ c) (h : xs.length ≤ c) :
    (seqs xs m).length ≤ (m + 1) * c ^ m := by
  induction m with
  | zero => simp [seqs]
  | succ m ih =>
    rw [seqs, List.length_append, length_tuples]
    have h1 : xs.length ^ (m + 1) ≤ c ^ (m + 1) := Nat.pow_le_pow_left h _
    have h2 : c ^ m ≤ c ^ (m + 1) := Nat.pow_le_pow_right hc (Nat.le_succ m)
    have h3 : (m + 1) * c ^ m ≤ (m + 1) * c ^ (m + 1) := Nat.mul_le_mul_left _ h2
    calc (seqs xs m).length + xs.length ^ (m + 1)
        ≤ (m + 1) * c ^ (m + 1) + c ^ (m + 1) := Nat.add_le_add (Nat.le_trans ih h3) h1
      _ = (m + 1 + 1) * c ^ (m + 1) := by rw [Nat.succ_mul (m + 1)]

theorem card_pos (t : Ty) : 1 ≤ card t := by
  induction t with
  | bool => simp [card]
  | int | quant | grid | enum => simp [card]; omega
  | str l c =>
    simp only [card]
    exact Nat.mul_pos (Nat.succ_pos _) (Nat.pow_pos (by omega))
  | list m t ih =>
    simp only [card]
    exact Nat.mul_pos (Nat.succ_pos _) (Nat.pow_pos ih)
  | unit => simp [card]
  | pair a b iha ihb => simp only [card]; exact Nat.mul_pos iha ihb
  | opt t ih => simp [card]

/-- **Capacity soundness.** -/
theorem length_vals_le (t : Ty) : (vals t).length ≤ card t := by
  induction t with
  | bool => simp [vals, card]
  | int | quant | grid | enum => simp [vals, steps, card]; omega
  | str l c =>
    simp only [vals, card, List.length_map]
    exact length_seqs_le _ _ _ (by omega) (by simp; omega)
  | list m t ih =>
    simp only [vals, card, List.length_map]
    exact length_seqs_le _ _ _ (card_pos t) ih
  | unit => simp [vals, card]
  | pair a b iha ihb =>
    simp only [vals, card]
    rw [length_flatMap_const _ (vals b).length _ (by intro x _; simp)]
    exact Nat.mul_le_mul iha ihb
  | opt t ih => simp [vals, card]; exact ih

/-! ## Everything released is enumerated -/

theorem mem_tuples {α : Type} (xs : List α) (l : List α) (h : ∀ x ∈ l, x ∈ xs) :
    l ∈ tuples xs l.length := by
  induction l with
  | nil => simp [tuples]
  | cons a l ih =>
    simp only [tuples, List.length_cons, List.mem_flatMap, List.mem_map]
    exact ⟨a, h a (by simp), l, ih (fun x hx => h x (by simp [hx])), rfl⟩

theorem mem_seqs {α : Type} (xs : List α) (l : List α) (m : Nat) (hm : l.length ≤ m)
    (h : ∀ x ∈ l, x ∈ xs) : l ∈ seqs xs m := by
  induction m with
  | zero =>
    have : l = [] := List.eq_nil_of_length_eq_zero (Nat.le_zero.mp hm)
    simp [seqs, this]
  | succ m ih =>
    rw [seqs, List.mem_append]
    by_cases hl : l.length ≤ m
    · exact Or.inl (ih hl)
    · have e : l.length = m + 1 := by omega
      exact Or.inr (e ▸ mem_tuples xs l h)

theorem mem_steps (lo p k : Int) (n : Nat) (h0 : 0 ≤ k) (h1 : k < n) :
    Val.num (lo + k * p) ∈ steps lo p n := by
  simp only [steps, List.mem_map, List.mem_range]
  exact ⟨k.toNat, by omega, by rw [Int.toNat_of_nonneg h0]⟩

theorem mapOpt_spec (f : Val → Option Val) (xs ys : List Val) (h : mapOpt f xs = some ys) :
    ys.length = xs.length ∧ ∀ y ∈ ys, ∃ x, f x = some y := by
  induction xs generalizing ys with
  | nil => simp [mapOpt] at h; subst h; simp
  | cons x xs ih =>
    simp only [mapOpt] at h
    split at h
    · rename_i y ys' hx hxs
      injection h with h; subst h
      obtain ⟨hl, hm⟩ := ih ys' hxs
      refine ⟨by simp [hl], ?_⟩
      intro z hz
      rcases List.mem_cons.mp hz with rfl | hz
      · exact ⟨x, hx⟩
      · exact hm z hz
    · exact absurd h (by simp)

theorem nearest_nonneg (lo hi : Int) (p : Nat) (x : Int) (hp : 0 < p) (h1 : lo ≤ x) (h2 : x ≤ hi) :
    0 ≤ nearest lo hi p x := by
  have a : 0 ≤ (2 * (x - lo) + p) / (2 * (p : Int)) := Int.ediv_nonneg (by omega) (by omega)
  have b : 0 ≤ (hi - lo) / (p : Int) := Int.ediv_nonneg (by omega) (by omega)
  simp only [nearest, lastStep]; omega

theorem nearest_le (lo hi : Int) (p : Nat) (x : Int) : nearest lo hi p x ≤ lastStep lo hi p := by
  simp only [nearest]; omega

theorem floor_bounds (lo hi : Int) (g : Nat) (x : Int) (hg : 0 < g) (h1 : lo ≤ x) (h2 : x ≤ hi) :
    0 ≤ (x - lo) / (g : Int) ∧ (x - lo) / (g : Int) ≤ lastStep lo hi g := by
  refine ⟨Int.ediv_nonneg (by omega) (by omega), ?_⟩
  simp only [lastStep]
  exact Int.ediv_le_ediv (by omega) (by omega)

/-- **The validator releases nothing outside `vals t`.** -/
theorem normalize_mem (t : Ty) (v w : Val) (h : normalize t v = some w) : w ∈ vals t := by
  induction t generalizing v w with
  | bool => cases v <;> simp [normalize] at h; subst h; rename_i b; cases b <;> simp [vals]
  | int lo hi =>
    cases v <;> simp [normalize] at h
    rename_i x
    obtain ⟨⟨h1, h2⟩, rfl⟩ := h
    have := mem_steps lo 1 (x - lo) (hi - lo + 1).toNat (by omega) (by omega)
    simp only [vals]
    rwa [show lo + (x - lo) * 1 = x by omega] at this
  | quant lo hi p =>
    cases v <;> simp [normalize] at h
    rename_i x
    obtain ⟨⟨hp, h1, h2⟩, rfl⟩ := h
    have a := nearest_nonneg lo hi p x hp h1 h2
    have b := nearest_le lo hi p x
    exact mem_steps _ _ _ _ a (by omega)
  | grid lo hi g =>
    cases v <;> simp [normalize] at h
    rename_i x
    obtain ⟨⟨hg, h1, h2⟩, rfl⟩ := h
    obtain ⟨a, b⟩ := floor_bounds lo hi g x hg h1 h2
    exact mem_steps _ _ _ _ a (by omega)
  | enum n => cases v <;> simp [normalize] at h; obtain ⟨hk, rfl⟩ := h; simp [vals, hk]
  | str l c =>
    cases v <;> simp [normalize] at h
    rename_i s
    obtain ⟨⟨hl, hc⟩, rfl⟩ := h
    simp only [vals, List.mem_map]
    exact ⟨s, mem_seqs _ _ _ hl (by intro x hx; simpa using hc x hx), rfl⟩
  | list m t ih =>
    cases v <;> simp [normalize] at h
    rename_i xs
    obtain ⟨hm, ys, hys, rfl⟩ := h
    obtain ⟨hl, hall⟩ := mapOpt_spec _ _ _ hys
    simp only [vals, List.mem_map]
    refine ⟨ys, mem_seqs _ _ _ (by omega) ?_, rfl⟩
    intro y hy
    obtain ⟨x, hx⟩ := hall y hy
    exact ih x y hx
  | unit => cases v <;> simp [normalize] at h; subst h; simp [vals]
  | pair a b iha ihb =>
    cases v <;> simp [normalize] at h
    rename_i x y
    split at h
    · rename_i x' y' hx hy
      injection h with h; subst h
      simp only [vals, List.mem_flatMap, List.mem_map]
      exact ⟨x', iha x x' hx, y', ihb y y' hy, rfl⟩
    · exact absurd h (by simp)
  | opt t ih =>
    by_cases hn : v = .null
    · subst hn; simp [normalize] at h; subst h; simp [vals]
    · have : normalize t v = some w := by cases v <;> simp_all [normalize]
      simp only [vals, List.mem_cons]
      exact Or.inr (ih v w this)

/-! ## Idempotence -/

theorem nearest_grid (lo hi : Int) (p : Nat) (k : Int) (hp : 0 < p) (hk : k ≤ lastStep lo hi p) :
    nearest lo hi p (lo + k * p) = k := by
  have e : (2 * (lo + k * p - lo) + (p : Int)) / (2 * p) = k := by
    have : 2 * (lo + k * (p : Int) - lo) + p = p + k * (2 * p) := by
      rw [show lo + k * (p : Int) - lo = k * p by omega]
      rw [Int.mul_left_comm k 2 (p : Int)]
      omega
    rw [this, Int.add_mul_ediv_right _ _ (by omega)]
    rw [Int.ediv_eq_zero_of_lt (by omega) (by omega)]
    omega
  simp only [nearest, e]
  omega

theorem step_in_range (lo hi : Int) (p : Nat) (k : Int) (hp : 0 < p) (h0 : 0 ≤ k)
    (hk : k ≤ lastStep lo hi p) : lo ≤ lo + k * p ∧ lo + k * p ≤ hi := by
  have a : 0 ≤ k * (p : Int) := Int.mul_nonneg h0 (by omega)
  have b : k * (p : Int) ≤ lastStep lo hi p * p := Int.mul_le_mul_of_nonneg_right hk (by omega)
  have c : lastStep lo hi p * (p : Int) ≤ hi - lo := Int.ediv_mul_le _ (by omega)
  omega

theorem mapOpt_fix (f : Val → Option Val) (ys : List Val) (h : ∀ y ∈ ys, f y = some y) :
    mapOpt f ys = some ys := by
  induction ys with
  | nil => rfl
  | cons y ys ih => simp [mapOpt, h y (by simp), ih (fun z hz => h z (by simp [hz]))]

/-- **Released values are fixed points.** -/
theorem normalize_idem (t : Ty) (v w : Val) (h : normalize t v = some w) :
    normalize t w = some w := by
  induction t generalizing v w with
  | bool => cases v <;> simp [normalize] at h; subst h; rfl
  | int lo hi =>
    cases v <;> simp [normalize] at h
    obtain ⟨hr, rfl⟩ := h
    simp [normalize, hr]
  | quant lo hi p =>
    cases v <;> simp [normalize] at h
    rename_i x
    obtain ⟨⟨hp, h1, h2⟩, rfl⟩ := h
    have b := nearest_le lo hi p x
    have r := step_in_range lo hi p _ hp (nearest_nonneg lo hi p x hp h1 h2) b
    simp [normalize, hp, r.1, r.2, nearest_grid lo hi p _ hp b]
  | grid lo hi g =>
    cases v <;> simp [normalize] at h
    rename_i x
    obtain ⟨⟨hg, h1, h2⟩, rfl⟩ := h
    obtain ⟨a, b⟩ := floor_bounds lo hi g x hg h1 h2
    have r := step_in_range lo hi g _ hg a b
    have e : (lo + (x - lo) / (g : Int) * g - lo) / (g : Int) = (x - lo) / g := by
      rw [show lo + (x - lo) / (g : Int) * g - lo = (x - lo) / g * g by omega]
      exact Int.mul_ediv_cancel _ (by omega)
    simp [normalize, hg, r.1, r.2, e]
  | enum n => cases v <;> simp [normalize] at h; obtain ⟨hk, rfl⟩ := h; simp [normalize, hk]
  | str l c =>
    cases v <;> simp [normalize] at h
    obtain ⟨hr, rfl⟩ := h
    simp only [normalize]
    rw [ite_eq_left hr]
  | list m t ih =>
    cases v <;> simp [normalize] at h
    rename_i xs
    obtain ⟨hm, ys, hys, rfl⟩ := h
    obtain ⟨hl, hall⟩ := mapOpt_spec _ _ _ hys
    have fix : mapOpt (normalize t) ys = some ys := mapOpt_fix _ _ fun y hy => by
      obtain ⟨x, hx⟩ := hall y hy
      exact ih x y hx
    simp [normalize, fix, hl, hm]
  | unit => cases v <;> simp [normalize] at h; subst h; rfl
  | pair a b iha ihb =>
    cases v <;> simp [normalize] at h
    rename_i x y
    split at h
    · rename_i x' y' hx hy
      injection h with h; subst h
      simp [normalize, iha x x' hx, ihb y y' hy]
    · exact absurd h (by simp)
  | opt t ih =>
    by_cases hn : v = .null
    · subst hn; simp [normalize] at h; subst h; rfl
    · have h' : normalize t v = some w := by cases v <;> simp_all [normalize]
      have f := ih v w h'
      by_cases hw : w = .null
      · subst hw; rfl
      · cases w <;> simp_all [normalize]

end Remit
