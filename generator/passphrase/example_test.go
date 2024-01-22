package passphrase

import "fmt"

func ExampleBasic() {
	// Genrate a 4 words passphrase
	passphrase, err := Basic()
	if err != nil {
		panic(err)
	}

	// Sample: hypocrisy-dean-collide-arguable
	fmt.Println(passphrase)
}

func ExampleStrong() {
	// Genrate a 8 words passphrase
	passphrase, err := Strong()
	if err != nil {
		panic(err)
	}

	// Sample: vertigo-iguana-hassle-unsolved-murky-skater-impeding-preteen
	fmt.Println(passphrase)
}

func ExampleParanoid() {
	// Genrate a 12 words passphrase
	passphrase, err := Paranoid()
	if err != nil {
		panic(err)
	}

	// Sample: subplot-spectrum-suspend-depose-unopposed-shrimp-cultural-filling-jury-desolate-power-carload
	fmt.Println(passphrase)
}

func ExampleDiceware() {
	// Genrate a 24 words passphrase (used by cryptowallet recovery maspter key)
	passphrase, err := Diceware(MasterWordCount)
	if err != nil {
		panic(err)
	}

	// Sample: ascend-unbridle-divorcee-shack-unsocial-litigator-graffiti-quarterly-rocky-overlap-uneaten-absolve-unlisted-levitate-geology-armoire-impale-scalding-drizzly-corral-importer-frigidly-correct-hacksaw
	fmt.Println(passphrase)
}
