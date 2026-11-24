import Lean.Data.Json
import RemitModel

/-! JSON-lines oracle for the differential tests: one request per line. -/
open Lean Remit

abbrev R := Except String

def int (j : Json) : R Int := j.getInt?
def nat (j : Json) : R Nat := j.getNat?
def at' (j : Json) (i : Nat) : R Json := j.getArrVal? i

partial def ty (j : Json) : R Ty := do
  match ← (← at' j 0).getStr? with
  | "bool" => pure .bool
  | "int" => pure <| .int (← int (← at' j 1)) (← int (← at' j 2))
  | "quant" => pure <| .quant (← int (← at' j 1)) (← int (← at' j 2)) (← nat (← at' j 3))
  | "grid" => pure <| .grid (← int (← at' j 1)) (← int (← at' j 2)) (← nat (← at' j 3))
  | "enum" => pure <| .enum (← nat (← at' j 1))
  | "str" => pure <| .str (← nat (← at' j 1)) (← nat (← at' j 2))
  | "list" => pure <| .list (← nat (← at' j 1)) (← ty (← at' j 2))
  | "unit" => pure .unit
  | "pair" => pure <| .pair (← ty (← at' j 1)) (← ty (← at' j 2))
  | "opt" => pure <| .opt (← ty (← at' j 1))
  | t => throw s!"type {t}"

partial def val (j : Json) : R Val := do
  match ← (← at' j 0).getStr? with
  | "null" => pure .null
  | "bool" => pure <| .bool (← (← at' j 1).getBool?)
  | "num" => pure <| .num (← int (← at' j 1))
  | "sym" => pure <| .sym (← nat (← at' j 1))
  | "str" => pure <| .str (← (← (← at' j 1).getArr?).toList.mapM nat)
  | "arr" => pure <| .arr (← (← (← at' j 1).getArr?).toList.mapM val)
  | "unit" => pure .unit
  | "pair" => pure <| .pair (← val (← at' j 1)) (← val (← at' j 2))
  | t => throw s!"value {t}"

partial def out : Val → Json
  | .null => toJson ["null"]
  | .bool b => .arr #["bool", toJson b]
  | .num i => .arr #["num", toJson i]
  | .sym n => .arr #["sym", toJson n]
  | .str s => .arr #["str", toJson s]
  | .arr xs => .arr #["arr", .arr (xs.map out).toArray]
  | .unit => toJson ["unit"]
  | .pair a b => .arr #["pair", out a, out b]

def facts (j : Json) : R Facts := do
  let b k := do (← j.getObjVal? k).getBool?
  let n k := do (← j.getObjVal? k).getNat?
  pure { decodes := ← b "decodes", signed := ← b "signed", addressed := ← b "addressed",
         unexpired := ← b "unexpired", notFuture := ← b "notFuture", shortLived := ← b "shortLived",
         nonce := ← n "nonce", analyzes := ← b "analyzes", authority := ← b "authority",
         permitted := ← b "permitted", withinClamps := ← b "withinClamps", approved := ← b "approved",
         bits := ← n "bits" }

def outcome : Outcome → Json
  | .rejected c => c
  | .counterOffer => "counter_offer"
  | .pendingApproval => "pending_approval"
  | .busy => "busy"
  | .admitted => "admitted"

def handle (line : String) : R Json := do
  let j ← Json.parse line
  match ← (← j.getObjVal? "op").getStr? with
  | "type" =>
    let t ← ty (← j.getObjVal? "type")
    let rs ← (← (← j.getObjVal? "values").getArr?).mapM fun v => do
      pure <| match normalize t (← val v) with
        | some w => out w
        | none => Json.null
    pure <| .mkObj [("card", toString (card t)), ("out", .arr rs)]
  | "ledger" =>
    let c : Cfg := { cap := ← nat (← j.getObjVal? "cap"), concurrency := ← nat (← j.getObjVal? "concurrency") }
    let mut l : Ledger := {}
    let mut acc := #[]
    for e in ← (← j.getObjVal? "events").getArr? do
      match e.getObjVal? "submit" with
      | .ok f =>
        let (l', o) := submit c l (← facts f)
        l := l'
        acc := acc.push (.arr #[outcome o, toJson l.used])
      | .error _ =>
        let s ← e.getObjVal? "settle"
        l := settle l (← nat (← at' s 0)) (← nat (← at' s 1))
        acc := acc.push (.arr #["settled", toJson l.used])
    pure (.arr acc)
  | o => throw s!"op {o}"

partial def main : IO Unit := do
  let stdin ← IO.getStdin
  let stdout ← IO.getStdout
  let rec loop : IO Unit := do
    let line ← stdin.getLine
    if line.isEmpty then return
    match handle line with
    | .ok j => stdout.putStrLn j.compress
    | .error e => stdout.putStrLn (Json.mkObj [("error", e)]).compress
    stdout.flush
    loop
  loop
