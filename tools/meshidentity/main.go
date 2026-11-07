package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/mhsanaei/3x-ui/v3/internal/meshidentity"
)

func run() error {
	input := flag.String("members", "", "operator member list JSON (no secrets)")
	output := flag.String("output", "", "NEW private output directory")
	flag.Parse()
	f, err := os.Open(*input)
	if err != nil {
		return err
	}
	defer f.Close()
	var members []meshidentity.Member
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(&members); err != nil {
		return err
	}
	if d.Decode(new(any)) != io.EOF {
		return fmt.Errorf("trailing member data")
	}
	return meshidentity.Generate(*output, members, time.Now().UTC())
}
func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Mesh identity generation failed:", err)
		os.Exit(1)
	}
	fmt.Println("Private identity bundle created. Mesh remains disabled until installed and enrolled.")
}
