# password

Package password provides a library for generating high-entropy random
password strings via the crypto/rand package.

## Constants

```golang
const (
    // MaxPasswordLen defines the upper bound for password generation length.
    MaxPasswordLen = 1024
)
```

## Variables

```golang
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
```

## Functions

### func [FromProfile](generator.go#L37)

`func FromProfile(p *Profile) (string, error)`

FromProfile uses given profile to generate a password which profile constraints.

```golang

password, err := FromProfile(ProfileStrong)
if err != nil {
    panic(err)
}

// Sample: S>P?E,O9S}zM7S={dc36P28607[9:|V+
fmt.Println(password)

```

### func [Generate](generator.go#L16)

`func Generate(length, numDigits, numSymbol int, noUpper, allowRepeat bool) (string, error)`

Generate a custom password

```golang

password, err := Generate(50, 10, 0, false, true)
if err != nil {
    panic(err)
}

// Sample: 8NmuyzUT8gAXli1kcD48ka3e59VXrhivloy0zrvNcpmBLmg2Fr
fmt.Println(password)

```

### func [NoSymbol](generator.go#L55)

`func NoSymbol() (string, error)`

NoSymbol generates a 32 character length password with 10 digits count,
no symbol, with all cases, and character repeat.

```golang

password, err := NoSymbol()
if err != nil {
    panic(err)
}

// Sample: fUEf3ni6GB7F5Rb84MHgIVy81gb7k4VX
fmt.Println(password)

```

### func [Paranoid](generator.go#L49)

`func Paranoid() (string, error)`

Paranoid generates a 64 character length password with 10 digits count,
10 symbol count, with all cases, and character repeat.

```golang

password, err := Paranoid()
if err != nil {
    panic(err)
}

// Sample: PGAgjiS"U27LA(mqptuH00tDUS43|@6lvf@MZ4[j7S5eqi`prEVKVYIrsp%oRc=/
fmt.Println(password)

```

### func [Strong](generator.go#L61)

`func Strong() (string, error)`

Strong generates a 32 character length password with 10 digits count,
10 symbol count, with all cases, and character repeat.

```golang

password, err := Strong()
if err != nil {
    panic(err)
}

// Sample: )2REh:6:k}2nT]061&!99Csj-O6N-=0Y
fmt.Println(password)

```

## Types

### type [Profile](profile.go#L4)

`type Profile struct { ... }`

Profile holds password generation settings

