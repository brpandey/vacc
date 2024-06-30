package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"math/rand"
	"strconv"
	"time"

	"github.com/bxcodec/faker/v3"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	mimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"

	"github.com/brpandey/vacc/circuit"
	"github.com/nats-io/nats.go"
)

// Define fake vaccine data and patient data schema
type VaccineData struct {
	VaccineType string `faker:"oneof:influenza,malaria,hepatitis_b"`
	//	LotNumber   string `faker:"uuid_hyphenated"`
	LotNumber string `faker:"cc_number"`
}

type PatientData struct {
	Dob string `faker:"date"`
	//	MedicalRecordNum string    `faker:"uuid_hyphenated"`
	MedicalRecordNum string `faker:"cc_number"`
}

type ProofRequest struct {
	Proof         []byte `json:"proof"`
	PublicWitness []byte `json:"public_witness"`
}

func main() {
	// Connect to NATS server using local default url
	nc, err := nats.Connect(nats.DefaultURL)
	if err != nil {
		log.Fatal(err)
	}
	defer nc.Close()

	// Seed for random data generation
	rand.Seed(time.Now().UnixNano())

	// Define vaccine circuit
	var circ circuit.VaccineCircuit

	// Compile the circuit to a R1CS (Rank-1 Constraint System) using Groth16 backend
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circ)
	if err != nil {
		panic(err)
	}

	// Aside from demonstration purposes,
	// this should be done in a trusted setup environment
	// Setup keys proving (private) and verifier (public)
	pk, _, err := groth16.Setup(r1cs)

	// Continuously generate data until user aborts
	for {
		// Generate artifical vaccine and patient data
		var vaccineData VaccineData
		var patientData PatientData

		// Generate vaccine data
		err := faker.FakeData(&vaccineData)
		if err != nil {
			log.Println("Failed to generate vaccine data:", err)
			continue
		}

		// Generate patient data
		err = faker.FakeData(&patientData)
		if err != nil {
			log.Println("Failed to generate patient data:", err)
			continue
		}

		fmt.Printf("patient dob is %s\n", patientData.Dob)

		dob, err := time.Parse("2006-01-02", patientData.Dob)
		if err != nil {
			fmt.Println("Error parsing date:", err)
			return
		}

		// Simulate age based on date of birth (for simplicity)
		age := int64(time.Since(dob).Hours()) / 24 / 365 // Approximate age in years

		lot, _ := strconv.Atoi(vaccineData.LotNumber)
		mrn, _ := strconv.Atoi(patientData.MedicalRecordNum)

		vac := rand.Intn(2) + 1
		vacHash := hash(vac)

		assign := circuit.VaccineCircuit{
			Age:              age,
			VaccineType:      rand.Intn(2),
			LotNumber:        lot,
			Dob:              dob.Unix(),
			MedicalRecordNum: mrn,
			VaccinatedSecret: vac,
			VaccinatedHash:   vacHash,
		}

		log.Printf("Assign variables %#v\n", &assign)

		witness, err := frontend.NewWitness(&assign, ecc.BN254.ScalarField())

		if err != nil {
			log.Fatal(err)
		}

		publicWitness, _ := witness.Public()

		fmt.Printf("%v", &publicWitness)

		proof, err := groth16.Prove(r1cs, pk, witness)

		if err != nil {
			log.Fatal(err)
		}

		var proof_buf bytes.Buffer
		proof.WriteRawTo(&proof_buf)

		var witness_buf bytes.Buffer
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
		subject := "vaccine.proof"

		if err := nc.Publish(subject, req); err != nil {
			log.Fatal(err)
		}

		fmt.Println("Proof sent successfully")

		// Periodically send proof
		time.Sleep(5 * time.Second)
	}
}

func hash(data int) []byte {
	var bigInt = big.NewInt(int64(data))
	var bytes = bigInt.Bytes()

	mimc := mimc.NewMiMC()
	mimc.Write(bytes)

	hash := mimc.Sum(nil)

	//        hi := big.NewInt(0).SetBytes(hash)
	//        log.Println("hash.String() is ", hi.String())

	return hash
}
