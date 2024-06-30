package circuit

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
)

const (
	malaria = iota
	hepatitisB
	influenza
)

const (
	vaccinated = iota + 1
	not_vaccinated
)

type VaccineCircuit struct {
	// Define circuit components and inputs
	Age              frontend.Variable `gnark:",public"`
	VaccineType      frontend.Variable `gnark:",public"`
	LotNumber        frontend.Variable `gnark:",public"`
	Dob              frontend.Variable
	MedicalRecordNum frontend.Variable
	VaccinatedSecret frontend.Variable
	VaccinatedHash   frontend.Variable `gnark:",public"`
}

// Construct circuit's constraints
func (circuit *VaccineCircuit) Define(api frontend.API) error {
	api.AssertIsLessOrEqual(circuit.Age, frontend.Variable(100))

	// Verify that vaccineType is "malaria", "hepatitis b", or "influenza"
	//        api.AssertIsLessOrEqual(circuit.VaccineType, frontend.Variable(influenza))

	vaccineTypeIsValid := api.Or(
		api.IsZero(api.Cmp(circuit.VaccineType, frontend.Variable(malaria))),
		api.IsZero(api.Cmp(circuit.VaccineType, frontend.Variable(hepatitisB))),
	)

	vaccineTypeIsValid = api.Or(
		vaccineTypeIsValid,
		api.IsZero(api.Cmp(circuit.VaccineType, frontend.Variable(influenza))),
	)

	api.Println("mimc circuit vaccinated secret is ", circuit.VaccinatedSecret)

	mimc, _ := mimc.NewMiMC(api)
	mimc.Write(circuit.VaccinatedSecret)
	sum := mimc.Sum()
	api.Println("mimc sum is ", sum)
	api.AssertIsEqual(circuit.VaccinatedHash, sum)

	return nil
}
