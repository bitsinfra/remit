package remit

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"unicode/utf8"
)

func Validate(rt any, params map[string]any, value any) error {
	normalized, err := jsonValue(rt)
	if err != nil {
		return err
	}
	if _, err = capacity(normalized, params, ""); err != nil {
		return err
	}
	value, err = jsonValue(value)
	if err != nil {
		return err
	}
	return validateValue(normalized, params, value, 0)
}

func validateValue(rt any, params map[string]any, value any, depth int) error {
	if depth > 128 {
		return errors.New("result nesting exceeds limit")
	}
	kind := "bool"
	var body any
	if s, ok := rt.(string); !ok || s != "bool" {
		object, ok := rt.(map[string]any)
		if !ok || len(object) != 1 {
			return errors.New("invalid result type")
		}
		for k, v := range object {
			kind, body = k, v
		}
	}
	bounds, _ := body.(map[string]any)
	bound := func(name string) any {
		v := bounds[name]
		if s, ok := v.(string); ok && len(s) > 0 && s[0] == '$' {
			return params[s[1:]]
		}
		return v
	}
	number := func(name string) float64 { n, _ := num(bound(name)); return n }
	valid := false
	switch kind {
	case "optional":
		if value == nil {
			return nil
		}
		return validateValue(body, params, value, depth+1)
	case "bool":
		_, valid = value.(bool)
	case "int":
		rational := func(v any) (*big.Rat, bool) {
			x, err := jsonValue(v)
			if err != nil {
				return nil, false
			}
			n, ok := x.(json.Number)
			if !ok {
				return nil, false
			}
			return new(big.Rat).SetString(string(n))
		}
		n, ok := rational(value)
		lo, lok := rational(bound("min"))
		hi, hik := rational(bound("max"))
		valid = ok && lok && hik && n.IsInt() && n.Cmp(lo) >= 0 && n.Cmp(hi) <= 0
	case "float", "decimal":
		n, ok := num(value)
		if s, text := value.(string); text && kind == "decimal" {
			var err error
			n, err = strconv.ParseFloat(s, 64)
			ok = err == nil
		}
		lo, hi := number("min"), number("max")
		valid = ok && !math.IsInf(n, 0) && !math.IsNaN(n) && n >= lo && n <= hi
		if valid && kind == "float" && bound("precision") != nil {
			step := number("precision")
			index := (n - lo) / step
			valid = math.Abs(index-math.Round(index)) <= 1e-6 && math.Round(index) <= math.Floor((hi-lo)/step+1e-9)
		}
		if valid && kind == "decimal" {
			s, text := value.(string)
			if n == 0 {
				n = 0
			}
			valid = text && s == strconv.FormatFloat(n, 'f', int(number("scale")), 64)
		}
	case "enum":
		values, ok := body.([]any)
		if !ok {
			values, _ = bounds["values"].([]any)
		}
		if s, ok := value.(string); ok {
			for _, v := range values {
				if s == v {
					valid = true
				}
			}
		}
	case "string":
		if s, ok := value.(string); ok && utf8.ValidString(s) && utf8.RuneCountInString(s) <= int(number("max_len")) {
			charset, _ := bounds["charset"].(string)
			patterns := map[string]string{"digits": "[0-9]*", "hex": "[0-9a-fA-F]*", "alpha": "[a-zA-Z]*", "alnum": "[a-zA-Z0-9]*", "base64": "[a-zA-Z0-9+/=_-]*", "ascii": "[ -~]*"}
			valid = true
			if pattern, found := patterns[charset]; found {
				valid, _ = regexp.MatchString("^(?:"+pattern+")$", s)
			}
			if pattern, ok := bounds["pattern"].(string); ok {
				matches, err := regexp.MatchString("^(?:"+pattern+")$", s)
				valid = valid && err == nil && matches
			}
		}
	case "bytes":
		if s, ok := value.(string); ok {
			decoded, err := base64.StdEncoding.Strict().DecodeString(s)
			valid = err == nil && len(decoded) <= int(number("max_len")) && base64.StdEncoding.EncodeToString(decoded) == s
		}
	case "timestamp", "date":
		if s, ok := value.(string); ok {
			n, nOK := tsMillis(s)
			lo, loOK := tsMillis(bound("min"))
			hi, hiOK := tsMillis(bound("max"))
			step := 864e5
			if kind == "timestamp" || bound("granularity") != nil {
				step, _ = duration(bound("granularity"))
			}
			valid = nOK && loOK && hiOK && n >= lo && n <= hi && math.Mod(n-lo, step) == 0
			if kind == "date" {
				matched, _ := regexp.MatchString(`^\d{4}-\d\d-\d\d$`, s)
				valid = valid && matched
			}
		}
	case "list", "table":
		max := "max"
		if kind == "table" {
			max = "max_rows"
		}
		if values, ok := value.([]any); ok && len(values) <= int(number(max)) {
			valid = true
			for _, item := range values {
				if err := validateValue(bounds["of"], params, item, depth+1); err != nil {
					return err
				}
			}
		}
	case "struct":
		if values, ok := value.(map[string]any); ok {
			valid = true
			for name := range values {
				if _, found := bounds[name]; !found {
					return fmt.Errorf("undeclared field %s", name)
				}
			}
			for name, field := range bounds {
				item, found := values[name]
				inner, _ := field.(map[string]any)
				if !found && inner["optional"] == nil {
					return fmt.Errorf("missing field %s", name)
				}
				if err := validateValue(field, params, item, depth+1); err != nil {
					return fmt.Errorf("%s: %w", name, err)
				}
			}
		}
	}
	if !valid {
		return fmt.Errorf("result does not inhabit %s", kind)
	}
	return nil
}
