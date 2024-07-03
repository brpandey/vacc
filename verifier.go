/// Verifier receives proof requests asynchronously from the prover
/// authenticates the proof for their validity without need personal data access
/// Optional TODO: Communicates verification result back to prover

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

                // Run the circuit along with the provided witness to verify that
                // the circuit equations pass muster.  If verification succeeds,
                // the user must have a valid vaccination
                if err := groth16.Verify(proof, vk, witness); err != nil {
                        fmt.Printf("Proof verification failed %v, patient doesn't have an active vaccination", err)
                        return
                }

                // E.g. Grant access to services
                fmt.Println("Proof verified successfully, patient passed vaccine authentication\n")
	})

	fmt.Printf("Awaiting vaccine proofs to be verified \n")
	select {}
}
