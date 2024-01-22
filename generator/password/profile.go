package password

// Profile holds password generation settings
type Profile struct {
	// Password total legnth.
	Length int
	// Digit count in generated password.
	NumDigits int
	// Symbol count in generated password.
	NumSymbol int
	// Allow/Disallow uppercase.
	NoUpper bool
	// Allow/Disallow character repetition.
	AllowRepeat bool
}

var (
	// ProfileParanoid defines 64 characters password with 10 symbol and 10 digits
	// with character repetition.
	//
	// Sample output: 2FXUH5pSW2Kad._5Ok:89f8|w?I&ftJKei+QFf\5`j9B+ykSFrCSUvciiR6KLEBv
	ProfileParanoid = &Profile{Length: 64, NumDigits: 10, NumSymbol: 10, NoUpper: false, AllowRepeat: true}

	// ProfileNoSymbol defines 32 characters password 10 digits with character repetition.
	//
	// Sample output: N9ITdLnPk2cx4Wme7i24HeGs786cz8Zz
	ProfileNoSymbol = &Profile{Length: 32, NumDigits: 10, NumSymbol: 0, NoUpper: false, AllowRepeat: true}

	// ProfileStrong defines 32 characters password with 10 symbols and 10 digits
	// with character repetition.
	//
	// Sample output: +75DRm71GEK?Bb03KGU!3_=7^9[N8`-`
	ProfileStrong = &Profile{Length: 32, NumDigits: 10, NumSymbol: 10, NoUpper: false, AllowRepeat: true}
)
