/-!
# Admission semantics and the bit ledger

Admission is a fixed sequence of checks; the first one that fails decides the
outcome. `admit` is total and looks only at facts, never at Sender prose.

Main results:
* `admitted_iff`     : a remit runs iff every check passed;
* `rejected_frozen`  : a remit that is not admitted charges nothing;
* `used_le_cap`      : no sequence of requests and settlements overdraws a
  budget, whatever the Sender does;
* `released_le_cap`  : total released bits never exceed the budget;
* `no_replay`        : a nonce is never admitted twice.
-/
namespace Remit

/-- What admission knows about one request. -/
structure Facts where
  decodes : Bool
  signed : Bool
  addressed : Bool
  unexpired : Bool
  notFuture : Bool
  shortLived : Bool
  nonce : Nat
  analyzes : Bool
  authority : Bool
  permitted : Bool
  withinClamps : Bool
  approved : Bool
  bits : Nat

inductive Outcome where
  | rejected (code : String)
  | counterOffer
  | pendingApproval
  | busy
  | admitted
deriving DecidableEq, Repr

structure Cfg where
  cap : Nat
  concurrency : Nat

/-- One principal's budget window. Settled bits were released; open
reservations may still be. -/
structure Ledger where
  settled : Nat := 0
  openBits : List Nat := []
  nonces : List Nat := []
  released : Nat := 0

def Ledger.used (l : Ledger) : Nat := l.settled + l.openBits.sum

def decide (c : Cfg) (l : Ledger) (f : Facts) : Outcome :=
  if !f.decodes then .rejected "RMT-E0002"
  else if !f.signed then .rejected "RMT-E0010"
  else if !f.addressed then .rejected "RMT-E0020"
  else if !f.unexpired then .rejected "RMT-E0021"
  else if !f.notFuture then .rejected "RMT-E0022"
  else if !f.shortLived then .rejected "RMT-E0023"
  else if l.nonces.contains f.nonce then .rejected "RMT-E0024"
  else if !f.analyzes then .rejected "analyze"
  else if !f.authority then .rejected "RMT-E0040"
  else if !f.permitted then .rejected "RMT-E0050"
  else if !f.withinClamps then .counterOffer
  else if !f.approved then .pendingApproval
  else if c.concurrency ≤ l.openBits.length then .busy
  else if c.cap < l.used + f.bits then .rejected "RMT-E0060"
  else .admitted

/-- A nonce is consumed once the freshness checks pass, unless the Holder was
merely busy. -/
def consumes (l : Ledger) (f : Facts) (o : Outcome) : Bool :=
  f.decodes && f.signed && f.addressed && f.unexpired && f.notFuture && f.shortLived
    && !l.nonces.contains f.nonce && o != .busy

def submit (c : Cfg) (l : Ledger) (f : Facts) : Ledger × Outcome :=
  let o := decide c l f
  let l1 := if consumes l f o then { l with nonces := f.nonce :: l.nonces } else l
  (if o = .admitted then { l1 with openBits := f.bits :: l1.openBits } else l1, o)

/-- Finish the `i`-th open run; actual use is clamped to the reservation. -/
def settle (l : Ledger) (i actual : Nat) : Ledger :=
  match l.openBits[i]? with
  | none => l
  | some b =>
    { l with settled := l.settled + min actual b, openBits := l.openBits.eraseIdx i,
             released := l.released + min actual b }

inductive Event where
  | submit (f : Facts)
  | settle (i actual : Nat)

def step (c : Cfg) (l : Ledger) : Event → Ledger
  | .submit f => (submit c l f).1
  | .settle i a => settle l i a

def run (c : Cfg) (es : List Event) : Ledger := es.foldl (step c) {}

theorem admitted_iff (c : Cfg) (l : Ledger) (f : Facts) :
    decide c l f = .admitted ↔
      f.decodes = true ∧ f.signed = true ∧ f.addressed = true ∧ f.unexpired = true
      ∧ f.notFuture = true ∧ f.shortLived = true ∧ l.nonces.contains f.nonce = false
      ∧ f.analyzes = true ∧ f.authority = true ∧ f.permitted = true ∧ f.withinClamps = true
      ∧ f.approved = true ∧ l.openBits.length < c.concurrency ∧ l.used + f.bits ≤ c.cap := by
  obtain ⟨d, si, ad, un, nf, sl, nonce, an, au, pe, wc, ap, bits⟩ := f
  simp only [decide]
  cases d; · simp
  cases si; · simp
  cases ad; · simp
  cases un; · simp
  cases nf; · simp
  cases sl; · simp
  cases hn : l.nonces.contains nonce
  case true => simp
  cases an; · simp
  cases au; · simp
  cases pe; · simp
  cases wc; · simp
  cases ap; · simp
  by_cases hc : c.concurrency ≤ l.openBits.length
  · simp [hc] <;> omega
  · by_cases hb : c.cap < l.used + bits
    · simp [hc, hb] <;> omega
    · simp [hc, hb] <;> omega

theorem rejected_frozen (c : Cfg) (l : Ledger) (f : Facts) (h : decide c l f ≠ .admitted) :
    (submit c l f).1.used = l.used ∧ (submit c l f).1.released = l.released := by
  simp only [submit, h, ite_false]
  split <;> simp [Ledger.used]

theorem sum_eraseIdx (xs : List Nat) (i b : Nat) (h : xs[i]? = some b) :
    (xs.eraseIdx i).sum + b = xs.sum := by
  induction xs generalizing i with
  | nil => simp at h
  | cons x xs ih =>
    cases i with
    | zero => simp at h; subst h; simp [Nat.add_comm]
    | succ i =>
      simp at h
      have := ih i h
      simp only [List.eraseIdx_cons_succ, List.sum_cons]
      omega

def Inv (c : Cfg) (l : Ledger) : Prop := l.used ≤ c.cap ∧ l.released ≤ l.settled

theorem inv_step (c : Cfg) (l : Ledger) (e : Event) (h : Inv c l) : Inv c (step c l e) := by
  obtain ⟨h1, h2⟩ := h
  cases e with
  | submit f =>
    by_cases ha : decide c l f = .admitted
    · have hb := (admitted_iff c l f).mp ha
      have hcap : l.used + f.bits ≤ c.cap := hb.2.2.2.2.2.2.2.2.2.2.2.2.2
      simp only [step, submit, ha, ite_true, Inv, Ledger.used] at *
      split <;> simp_all <;> omega
    · simp only [step, submit, ha, ite_false, Inv, Ledger.used] at *
      split <;> simp_all
  | settle i a =>
    simp only [step, settle]
    split
    · exact ⟨h1, h2⟩
    · rename_i b hb
      have hs := sum_eraseIdx l.openBits i b hb
      simp only [Inv, Ledger.used] at *
      omega

theorem inv_run (c : Cfg) (es : List Event) : Inv c (run c es) := by
  suffices ∀ l, Inv c l → Inv c (es.foldl (step c) l) from this {} (by simp [Inv, Ledger.used])
  induction es with
  | nil => intro l h; exact h
  | cons e es ih => intro l h; exact ih _ (inv_step c l e h)

/-- **No event sequence overdraws the budget.** -/
theorem used_le_cap (c : Cfg) (es : List Event) : (run c es).used ≤ c.cap := (inv_run c es).1

/-- **Released bits stay within the budget.** -/
theorem released_le_cap (c : Cfg) (es : List Event) : (run c es).released ≤ c.cap := by
  have h := inv_run c es
  have := h.1; have := h.2
  simp only [Ledger.used] at *
  omega

theorem mem_nonces_step (c : Cfg) (l : Ledger) (e : Event) (n : Nat) (h : n ∈ l.nonces) :
    n ∈ (step c l e).nonces := by
  cases e with
  | submit f =>
    simp only [step, submit]
    split <;> split <;> simp_all
  | settle i a =>
    simp only [step, settle]
    split <;> simp_all

theorem admitted_records (c : Cfg) (l : Ledger) (f : Facts) (h : decide c l f = .admitted) :
    f.nonce ∈ (submit c l f).1.nonces := by
  have hb := (admitted_iff c l f).mp h
  simp_all [submit, consumes]

/-- **A nonce is admitted at most once**, whatever happens in between. -/
theorem no_replay (c : Cfg) (l : Ledger) (f g : Facts) (es : List Event)
    (h : decide c l f = .admitted) (hn : g.nonce = f.nonce) :
    decide c (es.foldl (step c) (submit c l f).1) g ≠ .admitted := by
  have keep : ∀ (es : List Event) (l' : Ledger), f.nonce ∈ l'.nonces →
      f.nonce ∈ (es.foldl (step c) l').nonces := by
    intro es
    induction es with
    | nil => intro l' h'; exact h'
    | cons e es ih => intro l' h'; exact ih _ (mem_nonces_step c l' e _ h')
  have hm := keep es _ (admitted_records c l f h)
  intro ha
  have hb := (admitted_iff c _ g).mp ha
  simp_all

end Remit
