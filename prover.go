/// Prover generates zk-SNARK proof that person is vaccinated without revealing personal secret data

package main

import (
	"fmt"
	"log"
        "math/rand"
        "sync"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
        "github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"github.com/brpandey/vacc/circuit"
        "github.com/brpandey/vacc/setup"
        "github.com/brpandey/vacc/msg"

	"github.com/nats-io/nats.go"
)

var NUM_TRAVELERS = 50

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

        var wg sync.WaitGroup

	// Continuously generate data until user aborts to showcase stream of patient data
	for i:= 0; i < NUM_TRAVELERS; i++ {
                wg.Add(1)
                time.Sleep(2 * time.Second)

                go Prove(r1cs, pk, nc, &wg)
	}

        wg.Wait() // block until prove workers finished
}

func Prove(r1cs constraint.ConstraintSystem, pk groth16.ProvingKey, nc *nats.Conn, wg *sync.WaitGroup) {
        defer wg.Done()
        generated, flag := circuit.Generate()

        if !flag {
                return
        }

        // Generate a witness from the generated circuit which contains some randomness
        // and satisfies the equations of the circuit
        witness, err := frontend.NewWitness(&generated, ecc.BN254.ScalarField())

        if err != nil {
                log.Fatal(err)
        }

        publicWitness, _ := witness.Public()
        proof, err := groth16.Prove(r1cs, pk, witness)

        if err != nil {
                log.Printf("Unable to create valid proof, since constraints not met: %v\n\n", err)
                return
        }

        req := msg.Serialize(msg.NewRequest(proof, publicWitness))

        // Publish proof to NATS
        if err := nc.Publish(msg.Subject, req); err != nil {
                log.Fatal(err)
        }

        fmt.Println("Proof sent successfully\n")
}
