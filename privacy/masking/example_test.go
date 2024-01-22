package masking

import (
	"fmt"
	"net/netip"
	"strings"
)

func ExampleIP() {
	ips := []string{
		"8.8.8.8",
		"2001:db8:3333:4444:5555:6666:7777:8888",
	}

	var res []string
	for _, ip := range ips {
		out, err := IP(ip)
		if err != nil {
			panic(err)
		}

		res = append(res, out)
	}
	// Output:
	// 8.8.0.0
	// 2001:db8:3333::
	fmt.Println(strings.Join(res, "\n"))
}

func ExampleIPv4() {
	out, err := IPv4("8.8.8.8")
	if err != nil {
		panic(err)
	}

	// Output: 8.8.0.0
	fmt.Println(out)
}

func ExampleIPAddr() {
	ip, err := netip.ParseAddr("8.8.8.8")
	if err != nil {
		panic(err)
	}

	out, err := IPAddr(ip)
	if err != nil {
		panic(err)
	}

	// Output: 8.8.0.0
	fmt.Println(out)
}

func ExampleIPMask() {
	ip, err := netip.ParseAddr("8.8.8.8")
	if err != nil {
		panic(err)
	}

	out, err := IPMask(ip, 8)
	if err != nil {
		panic(err)
	}

	// Output: 8.8.8.0
	fmt.Println(out)
}

func ExampleHMAC() {
	key := []byte(`]P_Vk0tsK%:7Sq_;iOL.Oc:RQ>OO9B'zkhd<yba_e0V\&*5T1c|B%UH,BBi&Hu.`)

	out, err := HMAC("sensitive-data", key)
	if err != nil {
		panic(err)
	}

	// Output: vFh87CuJHak1VntcLiLDdI3_OYK8yEFo3AlSx91cHjs
	fmt.Println(out)
}

func ExampleNonDeterministicHMAC() {
	key := []byte(`]P_Vk0tsK%:7Sq_;iOL.Oc:RQ>OO9B'zkhd<yba_e0V\&*5T1c|B%UH,BBi&Hu.`)

	out, err := NonDeterministicHMAC("sensitive-data", key)
	if err != nil {
		panic(err)
	}

	// Sample: 6f8da4153a8005f7220b09e5dfdf7f43436a75c403674564abe1b7b2b451c39d98cbccca309b73b6
	fmt.Println(out)
}

func ExampleEmail() {
	out, err := Email("firstname.lastname@datadoghq.com")
	if err != nil {
		panic(err)
	}

	// Output: f****************e@d***********m
	fmt.Println(out)
}

func ExampleReserveMargin() {
	out, err := ReserveMargin("Datadog Privacy", 3, "*")
	if err != nil {
		panic(err)
	}

	// Output: Dat*********acy
	fmt.Println(out)
}

func ExampleReserveLeft() {
	out, err := ReserveLeft("Datadog Privacy", 3, "*")
	if err != nil {
		panic(err)
	}

	// Output: Dat************
	fmt.Println(out)
}

func ExampleReserveRight() {
	out, err := ReserveRight("Datadog Privacy", 3, "*")
	if err != nil {
		panic(err)
	}

	// Output: ************acy
	fmt.Println(out)
}
