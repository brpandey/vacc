package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/nats-io/nats.go"

        "github.com/brpandey/vacc/setup"
)

// The goal is to prove with zero-knowledge that a patient has taken a specific vaccine
// without disclosing any other personal information.

func main() {
	// Connect to NATS server
	nc, err := nats.Connect(nats.DefaultURL)
	if err != nil {
		log.Fatal(err)
	}
	defer nc.Close()

        vk := setup.ReadVKey()

	// Subscribe to proof messages
	nc.Subscribe(setup.MsgSubject, func(msg *nats.Msg) {
		var proofRequest setup.ProofRequest
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
