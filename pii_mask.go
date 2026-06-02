// cspell:ignore orhid
// Package piimask provides PII masking for PDF content text. Used by
// dump-redacted (in-process file dump) and safe-run (stdin/stdout
// wrapper that scrubs the output of any other util).
//
// Masking rules (in order):
//
//   - addresses (line-level keyword match)        -> <ADDR>
//   - IBANs (RO\d\d[A-Z0-9 ]{18,28} or generic)   -> <IBAN>
//   - emails                                      -> <EMAIL>
//   - phone-like runs                             -> <PHONE>
//   - "Platitor: …" / "Beneficiar: …" free text   -> "<label>: <PII>"
//   - dates dd.mm.yyyy / dd/mm/yyyy / dd-mm-yyyy  -> <DATE>
//   - decimal amounts (comma or dot)              -> <NUM>
//   - digit run >=2                               -> <D>
//   - title-case / all-caps token runs            -> <NAME>
//
// keepNames preserves a small allowlist of generic banking vocabulary
// (BCR, BRD, IBAN, RON, etc.) so structural markers stay visible.
package piimask

import (
	"regexp"
	"strings"
)

var (
	reIBAN  = regexp.MustCompile(`RO\d{2}[A-Z]{4}[0-9A-Z]{16}`)
	reIBAN2 = regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{12,30}\b`)
	// Space-separated IBAN — Garanti/TBI exports print groups of 4
	// chars: "RO21 TBIB 9311 0014 9466 0201". Catch this before the
	// generic digit-run / token-run filters mangle it.
	reIBANSpaced = regexp.MustCompile(`RO\d{2}\s[A-Z]{4}(?:\s[A-Z0-9]{4}){3,5}`)
	reEmail      = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	rePhone      = regexp.MustCompile(`(?:\+?40|0)\s?\d{2,3}[\s.\-]?\d{3}[\s.\-]?\d{3,4}`)
	reDate       = regexp.MustCompile(`\b\d{1,2}[./\-]\d{1,2}[./\-]\d{2,4}\b`)
	reAmt        = regexp.MustCompile(`-?\d{1,3}(?:[.\s]\d{3})*,\d{2}\b|-?\d+\.\d{2}\b`)
	reDig        = regexp.MustCompile(`\d{2,}`)

	// addresses: line-level scrub.
	reAddrLine = regexp.MustCompile(`(?i)\b(?:soseaua|sos\.|strada|str\.|calea|bulevardul|b-?dul|aleea|piata|splaiul|drumul|cartier|nr\.?|bl\.|sc\.|et\.|ap\.|sector|judet|cod\s*postal|post\s*code|bucuresti|bucharest|cluj|timisoara|iasi|brasov|constanta|sibiu|oradea|building|floor|district|road|street|avenue|boulevard|orhideelor|orhid|the\s+bridge)\b`)

	// after these labels everything until ; or end-of-line is free-text PII.
	reLabelPII = regexp.MustCompile(`(?i)(Platitor|Beneficiar|Detalii|Titular|Owner|Beneficiary|Payer|Beneficiarul|Platitorul|Ordonator|Beneficiar Final|Reprezentant|Administrator|Asociat|Client|Pentru\s+contul|pe\s+numele)\s*[:\-]\s*[^;\n]+`)

	// title-case or all-caps token (allow single letters: "S", "R", "L" for SRL).
	reTokenRun = regexp.MustCompile(`\b(?:[A-ZĂÂÎȘȚ][A-ZĂÂÎȘȚa-zăâîșț\.]*\s*&?\s*){2,}`)

	// keywords we let through if a run is *entirely* made of them.
	keepNames = map[string]bool{
		"BCR": true, "BRD": true, "ING": true, "BT": true,
		"BANCA": true, "TRANSILVANIA": true, "RAIFFEISEN": true, "UNICREDIT": true,
		"GARANTI": true, "TBI": true, "LIBRA": true, "CEC": true,
		"IBAN": true, "RON": true, "EUR": true, "USD": true, "GBP": true,
		"COD": true, "CIF": true, "CUI": true, "CNP": true, "CODFISC": true,
		"DEBIT": true, "CREDIT": true, "SOLD": true, "INITIAL": true, "FINAL": true,
		"CONTABIL": true, "SUMA": true, "EXTRAS": true, "CONT": true,
		"MISCARI": true, "RULAJ": true, "TOTAL": true, "PE": true,
		"INTERNET": true, "BANK": true, "PAYMENTS": true, "UAB": true,
		"PAGINA": true, "PAG": true, "DIN": true, "DATE": true, "PAGE": true, "OF": true,
		"TIP": true, "DATA": true, "REFERINTA": true, "DETALII": true,
		"TRANZACTIE": true, "OPERATIUNE": true, "DESCRIERE": true,
		"DEPOSIT": true, "BALANCE": true, "VALUE": true, "OPERATION": true, "REFERENCE": true, "BILL": true,
		"S.A.": true, "SA": true, "SRL": true, "S.R.L.": true,
		"NUM": true, "DATE_": true,
		"VIVA": true, "WALLET": true, "MONEY": true, "PERIOD": true,
		"ACCOUNT": true, "NUMBER": true, "CURRENCY": true,
		"DESCRIPTION": true, "AMOUNT": true, "TRANSACTION": true,
		"MAROUSI": true, "ATHENS": true, "EXTRAIT": true,
	}
)

func tokensAllKeyword(run string) bool {
	parts := strings.FieldsFunc(run, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '-' || r == ',' || r == '.'
	})
	if len(parts) == 0 {
		return false
	}
	for _, p := range parts {
		up := strings.ToUpper(p)
		up = strings.TrimRight(up, ".")
		if !keepNames[up] {
			return false
		}
	}
	return true
}

// Mask returns the PII-masked form of a single line. Address-shaped
// lines are collapsed to "<ADDR>" so the spatial structure of the
// surrounding dump is preserved one line per logical row.
func Mask(line string) string {
	if reAddrLine.MatchString(line) {
		return "<ADDR>"
	}
	s := line
	s = reIBANSpaced.ReplaceAllString(s, "<IBAN>")
	s = reIBAN.ReplaceAllString(s, "<IBAN>")
	s = reIBAN2.ReplaceAllString(s, "<IBAN>")
	s = reEmail.ReplaceAllString(s, "<EMAIL>")
	s = rePhone.ReplaceAllString(s, "<PHONE>")
	s = reLabelPII.ReplaceAllStringFunc(s, func(m string) string {
		ID := strings.IndexAny(m, ":-")
		if ID < 0 {
			return "<PII>"
		}
		return m[:ID+1] + " <PII>"
	})
	s = reDate.ReplaceAllString(s, "<DATE>")
	s = reAmt.ReplaceAllString(s, "<NUM>")
	s = reDig.ReplaceAllString(s, "<D>")
	s = reTokenRun.ReplaceAllStringFunc(s, func(m string) string {
		if tokensAllKeyword(m) {
			return m
		}
		return "<NAME>"
	})
	return s
}

// MaskStream masks a multi-line text block, preserving line breaks.
func MaskStream(text string) string {
	if text == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(text))
	start := 0
	for i, r := range text {
		if r == '\n' {
			b.WriteString(Mask(text[start:i]))
			b.WriteByte('\n')
			start = i + 1
		}
	}
	if start < len(text) {
		b.WriteString(Mask(text[start:]))
	}
	return b.String()
}
