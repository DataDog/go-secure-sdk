# passphrase

Package passphrase provides passphrase generation based on DiceWare.

Passphrases are used for highly sensitive secrets such as master keys.

## Constants

```golang
const (
    // MinWordCount defines the lowest bound for allowed word count.
    MinWordCount = 4
    // MaxWordCount defines the highest bound for allowed word count.
    MaxWordCount = 24
    // BasicWordCount defines basic passphrase word count (4 words).
    BasicWordCount = 4
    // StrongWordCount defines strong passphrase word count (8 words).
    StrongWordCount = 8
    // ParanoidWordCount defines paranoid passphrase word count (12 words).
    ParanoidWordCount = 12
    // MasterWordCount defines master passphrase word count (24 words).
    MasterWordCount = 24
)
```

## Functions

### func [Basic](generator.go#L49)

`func Basic() (string, error)`

Basic generates 4 words diceware passphrase.

```golang

// Genrate a 4 words passphrase
passphrase, err := Basic()
if err != nil {
    panic(err)
}

// Sample: hypocrisy-dean-collide-arguable
fmt.Println(passphrase)

```

### func [Diceware](generator.go#L29)

`func Diceware(count int) (string, error)`

Diceware generates a passphrase using english words.

```golang

// Genrate a 24 words passphrase (used by cryptowallet recovery maspter key)
passphrase, err := Diceware(MasterWordCount)
if err != nil {
    panic(err)
}

// Sample: ascend-unbridle-divorcee-shack-unsocial-litigator-graffiti-quarterly-rocky-overlap-uneaten-absolve-unlisted-levitate-geology-armoire-impale-scalding-drizzly-corral-importer-frigidly-correct-hacksaw
fmt.Println(passphrase)

```

### func [Master](generator.go#L64)

`func Master() (string, error)`

Master generates 24 words diceware passphrase.

### func [Paranoid](generator.go#L59)

`func Paranoid() (string, error)`

Paranoid generates 12 words diceware passphrase.

```golang

// Genrate a 12 words passphrase
passphrase, err := Paranoid()
if err != nil {
    panic(err)
}

// Sample: subplot-spectrum-suspend-depose-unopposed-shrimp-cultural-filling-jury-desolate-power-carload
fmt.Println(passphrase)

```

### func [Strong](generator.go#L54)

`func Strong() (string, error)`

Strong generates 8 words diceware passphrase.

```golang

// Genrate a 8 words passphrase
passphrase, err := Strong()
if err != nil {
    panic(err)
}

// Sample: vertigo-iguana-hassle-unsolved-murky-skater-impeding-preteen
fmt.Println(passphrase)

```

