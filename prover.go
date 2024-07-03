/// Prover generates zk-SNARK proof that person is vaccinated without revealing personal secret data

package main

import (
	"fmt"
	"log"
        "math/rand"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"github.com/brpandey/vacc/circuit"
        "github.com/brpandey/vacc/setup"
        "github.com/brpandey/vacc/msg"

	"github.com/nats-io/nats.go"
)

func main() {
	// Connect to NATS server using local default url
	nc, err := nats.Connect(nats.DefaultURL)
	if err != nil {
		log.Fatal(err)
	}
	defer nc.Close()

	// Seed for random data generation
	rand.Seed(time.Now().UnixNano())

        // Initialize "trusted setup"
        r1cs, pk := setup.Initialize()

	// Continuously generate data until user aborts to showcase stream of patient data
	for {
                time.Sleep(5 * time.Second)
                generated, flag := circuit.Generate()

                if !flag {
                        continue
                }

                // Generate a witness from the generated circuit which contains some randomness
                // and satisfies the equations of the circuit
		witness, err := frontend.NewWitness(&generated, ecc.BN254.ScalarField())

		if err != nil {
                        log.Println("waka0")
			log.Fatal(err)
		}

		publicWitness, _ := witness.Public()
		proof, err := groth16.Prove(r1cs, pk, witness)

		if err != nil {
			log.Printf("Unable to create valid proof, since constraints not met: %v\n\n", err)

                        continue
		}

                req := msg.Serialize(msg.NewRequest(proof, publicWitness))

		// Publish proof to NATS
		if err := nc.Publish(msg.Subject, req); err != nil {
			log.Fatal(err)
		}

		fmt.Println("Proof sent successfully\n")
	}
}
