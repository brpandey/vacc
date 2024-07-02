package setup

import (
        "bytes"
        "encoding/base64"
        "github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
        "github.com/consensys/gnark/constraint"
        "github.com/consensys/gnark-crypto/ecc"
        "github.com/consensys/gnark/backend/groth16"
        "github.com/brpandey/vacc/circuit"

        "log"
        "os"
)

const envKeyProver = "Prover"

func Initialize() (constraint.ConstraintSystem, groth16.ProvingKey) {
        // Define vaccine circuit
        var circ circuit.VaccineCircuit

        // Compile the circuit to a R1CS (Rank-1 Constraint System) using Groth16 backend
        r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circ)

        if err != nil {
                log.Fatal(err)
        }

        // Setup both keys: proving (private) and verifier (public)
        pk, vk, err := groth16.Setup(r1cs)

        //SerializePKey(pk)
        SerializeVKey(vk)

        return r1cs, pk
}

func ReadPKey(clear bool) groth16.ProvingKey {
        pkString, flag := os.LookupEnv(envKeyProver)

        if !flag {
                log.Fatal("env key not found: ", envKeyProver)
        }

        if clear {
                os.Unsetenv(envKeyProver)
        }

        pkeyBuf, err := base64.StdEncoding.DecodeString(pkString)
        if err != nil {
		log.Fatal(err)
	}

        data := bytes.NewBuffer(pkeyBuf)

        pk := groth16.NewProvingKey(ecc.BN254)
        pk.ReadFrom(data)
        return pk
}

func ReadVKey() groth16.VerifyingKey {
        // Read precomputed verifier key from file
	file, err := os.ReadFile("verify.key")
	if err != nil {
		log.Fatal(err)
	}

	keyBuf := *bytes.NewBuffer(file)
        vk := groth16.NewVerifyingKey(ecc.BN254)
        vk.ReadFrom(&keyBuf)
        return vk
}

func SerializePKey(pk groth16.ProvingKey) {
        // Serialize pk to env var instead of to file
        var pkeyBuf bytes.Buffer
        pk.WriteTo(&pkeyBuf)
        pkString := base64.StdEncoding.EncodeToString(pkeyBuf.Bytes())

        os.Setenv(envKeyProver, pkString)
}

func SerializeVKey(vk groth16.VerifyingKey) {
        /* Serialize verifier key for easy deserialization by verifier process
           Only changes once upon r1cs setup -- prover needs to be started first for proper synchronization
           Doesn't need to be sent on each proof message */
	var keyBuf bytes.Buffer
	vk.WriteTo(&keyBuf)

	err := os.WriteFile("verify.key", keyBuf.Bytes(), 0644)

	if err != nil {
		log.Fatal(err)
	}
}
