package main

import (
	"fmt"
	"log"

	"github.com/consensys/gnark/backend/groth16"
	"github.com/nats-io/nats.go"

        "github.com/brpandey/vacc/setup"
        "github.com/brpandey/vacc/msg"
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
	nc.Subscribe(msg.Subject, func(message *nats.Msg) {
                proof, witness := msg.Deserialize(message.Data)

                if err := groth16.Verify(proof, vk, witness); err != nil {
                        fmt.Println("Proof verification failed:", err)
                        return
                }

                fmt.Println("Proof verified successfully\n")
	})

	fmt.Printf("Awaiting vaccine proofs to be verified \n")
	select {}
}
