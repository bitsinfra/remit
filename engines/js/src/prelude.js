// Remit kernel prelude (Holder-trusted). Builds the `reads` object and the
// lazy, columnar Table wrapper. Evaluated before Sender code.
"use strict";
(function () {
  const call = globalThis.__remit_call;
  const declaredFn = globalThis.__remit_declared;
  const colFn = globalThis.__remit_col;
  const holderFn = globalThis.__remit_fn;
  delete globalThis.__remit_call;
  delete globalThis.__remit_col;
  delete globalThis.__remit_fn;
  delete globalThis.__remit_declared;

  const TIME = new Set(["timestamp", "date"]);

  class Table {
    #t; #rows; #cols;
    constructor(t) {
      this.#t = t;
      this.#cols = new Array(t.names.length);
      this.#rows = null;
      Object.defineProperty(this, "length", { value: t.n, enumerable: true });
      Object.defineProperty(this, "schema", {
        value: Object.freeze(t.names.map((name, i) => Object.freeze({ name, type: t.types[i] }))),
        enumerable: true,
      });
    }
    #raw(i) { return (this.#cols[i] ??= colFn(this.#t.id, i)); }
    /** Column as a typed array (numbers, timestamps as epoch ms) or plain array. */
    col(name) {
      const i = this.#t.names.indexOf(name);
      if (i < 0) throw new TypeError(`unknown column \`${name}\``);
      const ty = this.#t.types[i];
      const v = this.#raw(i);
      if (ty === "float" || ty === "int" || TIME.has(ty)) {
        const out = new Float64Array(v.length);
        for (let j = 0; j < v.length; j++) out[j] = v[j] === null ? NaN : v[j];
        return out;
      }
      return v.slice();
    }
    /** Materialize rows as objects (timestamps/dates become Date). */
    rows() {
      if (this.#rows) return this.#rows;
      const { names, types, n } = this.#t;
      const columns = names.map((_, i) => this.#raw(i));
      const out = new Array(n);
      for (let r = 0; r < n; r++) {
        const o = {};
        for (let c = 0; c < names.length; c++) {
          const x = columns[c][r];
          o[names[c]] = x !== null && TIME.has(types[c]) ? new Date(x) : x;
        }
        out[r] = o;
      }
      this.#rows = out;
      return out;
    }
    [Symbol.iterator]() { return this.rows()[Symbol.iterator](); }
    map(f) { return this.rows().map(f); }
    filter(f) { return this.rows().filter(f); }
    reduce(f, init) { return arguments.length > 1 ? this.rows().reduce(f, init) : this.rows().reduce(f); }
    forEach(f) { this.rows().forEach(f); }
    some(f) { return this.rows().some(f); }
    every(f) { return this.rows().every(f); }
    find(f) { return this.rows().find(f); }
    slice(a, b) { return this.rows().slice(a, b); }
    at(i) { return this.rows().at(i); }
  }

  // Reads are bound per remit (at `load`), after the engine was pre-initialized.
  let made = null;
  globalThis.__remit_make_reads = function () {
    if (made) return made;
    const reads = {};
    for (const name of declaredFn()) {
      const fn = (params) => new Table(call(name, params === undefined ? {} : params));
      Object.defineProperty(fn, "name", { value: name });
      reads[name] = Object.freeze(fn);
    }
    made = Object.freeze(reads);
    delete globalThis.__remit_make_reads;
    return made;
  };
  globalThis.Table = Table;
  /** Holder functions (`holder.call("embed", text)`): pure, priced in fuel. */
  Object.defineProperty(globalThis, "holder", {
    value: Object.freeze({ call: (name, args) => holderFn(String(name), args === undefined ? null : args) }),
  });
})();
