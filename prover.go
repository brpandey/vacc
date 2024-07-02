package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
        "math/rand"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"github.com/brpandey/vacc/circuit"
        "github.com/brpandey/vacc/setup"

	"github.com/nats-io/nats.go"
)

type ProofRequest struct {
	Proof         []byte `json:"proof"`
	PublicWitness []byte `json:"public_witness"`
}

const subject = "vaccine.proof"

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
        // ProvingKey could be returned as variable or as env variable if multiple provers..
        r1cs := setup.Initialize()
        pk := setup.ReadPKey(true)

	// Continuously generate data until user aborts to showcase stream of patient data
	for {
                generated, flag := circuit.Generate()

                if !flag {
                        continue
                }

		witness, err := frontend.NewWitness(&generated, ecc.BN254.ScalarField())

		if err != nil {
			log.Fatal(err)
		}

		publicWitness, _ := witness.Public()
		proof, err := groth16.Prove(r1cs, pk, witness)

		if err != nil {
			log.Fatal(err)
		}

		var proof_buf, witness_buf bytes.Buffer
		proof.WriteRawTo(&proof_buf)
		publicWitness.WriteTo(&witness_buf)

		// Create proof request
		request := ProofRequest{
			Proof:         proof_buf.Bytes(),
			PublicWitness: witness_buf.Bytes(),
		}

		req, err := json.Marshal(request)

		if err != nil {
			fmt.Println("Error marshalling request:", err)
			return
		}

		// Publish proof to NATS
		if err := nc.Publish(subject, req); err != nil {
			log.Fatal(err)
		}

		fmt.Println("Proof sent successfully\n")

		// Periodically send proof
		time.Sleep(5 * time.Second)
	}
}
