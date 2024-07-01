package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
        "os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/nats-io/nats.go"

	"github.com/brpandey/vacc/circuit"
)

type ProofRequest struct {
	Proof         []byte `json:"proof"`
	PublicWitness []byte `json:"public_witness"`
}

// The goal is to prove with zero-knowledge that a patient has taken a specific vaccine
// without disclosing any other personal information.

func main() {
	// Connect to NATS server
	nc, err := nats.Connect(nats.DefaultURL)
	if err != nil {
		log.Fatal(err)
	}
	defer nc.Close()

	var circ circuit.VaccineCircuit

	// Compile the circuit to a R1CS (Rank-1 Constraint System) using Groth16 backend
	_, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circ)
	if err != nil {
		panic(err)
	}

        /* Read precomputed verifier key from file */
	file, err := os.ReadFile("verify.key")
	if err != nil {
		log.Fatal(err)
	}

	keyBuf := *bytes.NewBuffer(file)
        vk := groth16.NewVerifyingKey(ecc.BN254)
        vk.ReadFrom(&keyBuf)

	// Subscribe to proof messages
	nc.Subscribe("vaccine.proof", func(msg *nats.Msg) {
		var proofRequest ProofRequest
		if err := json.Unmarshal(msg.Data, &proofRequest); err != nil {
			fmt.Println("Error decoding proof request:", err)
			return
		}

		// Unmarshal proof
		proof := groth16.NewProof(ecc.BN254)
		witness, _ := witness.New(ecc.BN254.ScalarField())

		proof.ReadFrom(bytes.NewBuffer(proofRequest.Proof))
		witness.ReadFrom(bytes.NewBuffer(proofRequest.PublicWitness))

                if err := groth16.Verify(proof, vk, witness); err != nil {
                        fmt.Println("Proof verification failed:", err)
                        return
                }

                fmt.Println("Proof verified successfully\n")
	})

	fmt.Printf("Awaiting vaccine proofs to be verified \n")
	select {}
}
