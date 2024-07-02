package circuit

import (
        "github.com/bxcodec/faker/v3"

        "github.com/consensys/gnark/frontend"
        "github.com/consensys/gnark/std/hash/mimc"
	mimc2 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"

	"strconv"
	"time"
        "log"
	"math/big"
	"math/rand"

)

const (
	malaria = iota
	hepatitisB
	influenza
)

const (
	vaccinated = iota + 1
	notVaccinated
)

// The goal of the circuit is to structure the data to prove with zero-knowledge
// that a patient has taken a specific vaccine
// without disclosing any other highly personal information (dob, mrn).

// TODO -- mrn and dob should be hashed instead of vaccinated status

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


const dateFormat = "2006-01-02"

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


// Generate vaccine circuit fields using faker library
func Generate() (VaccineCircuit, bool) {
        // Generate vaccine and patient data
        var vaccineData VaccineData
        var patientData PatientData

        // Generate vaccine data
        err := faker.FakeData(&vaccineData)
        if err != nil {
                log.Println("Failed to generate vaccine data:", err)
                return VaccineCircuit{}, false
        }

        // Generate patient data
        err = faker.FakeData(&patientData)
        if err != nil {
                log.Println("Failed to generate patient data:", err)
                return VaccineCircuit{}, false
        }

        dob, err := time.Parse(dateFormat, patientData.Dob)
        if err != nil {
                log.Fatal("Error parsing date:", err)
        }

        // Simulate age based on date of birth (for simplicity)
        age := int64(time.Since(dob).Hours()) / 24 / 365 // Approximate age in years

        lot, _ := strconv.Atoi(vaccineData.LotNumber)
        mrn, _ := strconv.Atoi(patientData.MedicalRecordNum)

        vac := rand.Intn(2) + 1
        vacHash := hash(vac)

        gen := VaccineCircuit{
                Age:              age,
                VaccineType:      rand.Intn(2),
                LotNumber:        lot,
                Dob:              dob.Unix(),
                MedicalRecordNum: mrn,
                VaccinatedSecret: vac,
                VaccinatedHash:   vacHash,
        }

        log.Printf("Generated circuit variables %#v\n", &gen)
        return gen, true
}

func hash(data int) []byte {
	var bigInt = big.NewInt(int64(data))
	var bytes = bigInt.Bytes()

	mc := mimc2.NewMiMC()
	mc.Write(bytes)

	hash := mc.Sum(nil)

	//        hi := big.NewInt(0).SetBytes(hash)
	//        log.Println("hash.String() is ", hi.String())

	return hash
}
