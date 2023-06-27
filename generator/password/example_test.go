// SPDX-FileCopyrightText: 2023-present Datadog, Inc.
// SPDX-License-Identifier: Apache-2.0

package password

import "fmt"

func ExampleFromProfile() {
	password, err := FromProfile(ProfileStrong)
	if err != nil {
		panic(err)
	}

	// Sample: S>P?E,O9S}zM7S={dc36P28607[9:|V+
	fmt.Println(password)
}

func ExampleParanoid() {
	password, err := Paranoid()
	if err != nil {
		panic(err)
	}

	// Sample: PGAgjiS"U27LA(mqptuH00tDUS43|@6lvf@MZ4[j7S5eqi`prEVKVYIrsp%oRc=/
	fmt.Println(password)
}

func ExampleNoSymbol() {
	password, err := NoSymbol()
	if err != nil {
		panic(err)
	}

	// Sample: fUEf3ni6GB7F5Rb84MHgIVy81gb7k4VX
	fmt.Println(password)
}

func ExampleStrong() {
	password, err := Strong()
	if err != nil {
		panic(err)
	}

	// Sample: )2REh:6:k}2nT]061&!99Csj-O6N-=0Y
	fmt.Println(password)
}

func ExampleGenerate() {
	password, err := Generate(50, 10, 0, false, true)
	if err != nil {
		panic(err)
	}

	// Sample: 8NmuyzUT8gAXli1kcD48ka3e59VXrhivloy0zrvNcpmBLmg2Fr
	fmt.Println(password)
}
