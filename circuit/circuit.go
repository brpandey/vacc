package circuit

import (
        "github.com/bxcodec/faker/v3"

        "github.com/consensys/gnark/frontend" // gnark high-level circuit api
        "github.com/consensys/gnark/std/hash/mimc" // mimc is a one-way hash function suitable for ec and zkp
	mimc2 "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"

	"strconv"
	"time"
        "log"
	"math/big"
	"math/rand"

)

const (
	measles = iota
        //	hepatitisB
        yellowFever //https://wwwnc.cdc.gov/travel/yellowbook/2024/infections-diseases/yellow-fever
)

const (
	vaccinated = iota + 1
	notVaccinated
)

const (
	ghana = iota // https://wwwnc.cdc.gov/travel/destinations/traveler/none/ghana
	sriLanka // https://wwwnc.cdc.gov/travel/destinations/traveler/none/sri-lanka
        japan
)

const dateFormat = "2006-01-02"

// Define fake vaccine data and patient data schema
type VaccineData struct {
	Type string `faker:"oneof:measles,yellowFever"`
	LotNumber string `faker:"cc_number"`
        ExpDate string `faker:"date"`
}

type PatientData struct {
	Dob string `faker:"date"`
	MedicalRecordNum string `faker:"cc_number"`
}


// The goal of the circuit is to structure the data to prove with zero-knowledge
// that a patient has had a specific vaccine without disclosing any other
// highly personal (secretive) information (detailed DOB, specific MRN).

// The circuit combined with its constraints comprise a set of equations that represent
// the vaccine data along with patient info split along public and private fields of information


// The circuit proof, if generated successfully, Will prove that the travel vaccination
// has been successful given three parts being true:

// Whether they were (1) vaccinated, if they adhered (2) to the country's
// travel vaccination rules, (3) if the vaccination is still valid and hasn't expired

type VaccineCircuit struct {
	// Define circuit components and inputs
	Age              frontend.Variable `gnark:",public"`
	VaccineType      frontend.Variable `gnark:",public"`
	LotNumber        frontend.Variable
	Dob              frontend.Variable
	MedicalRecordNum frontend.Variable
        MedicalRecordHash frontend.Variable `gnark:",public"` // Person medical ID hash
        CountryFrom      frontend.Variable `gnark:",public"` // Origin country
        CountryTo        frontend.Variable `gnark:",public"` // Travel destination country

	VaccinatedSecret frontend.Variable
        VaccineExpDate   frontend.Variable
}

// Construct circuit's constraints
func (circuit *VaccineCircuit) Define(api frontend.API) error {
        // setup some simple markers for later use
        noRisk := frontend.Variable(0)
        isVaccinated := frontend.Variable(1)

        // Constraint #1: if type is measles, must be vaccinated for it
	measlesVaccinated := api.Select(
		api.IsZero(api.Cmp(circuit.VaccineType, frontend.Variable(measles))),
		api.IsZero(api.Cmp(circuit.VaccinatedSecret, isVaccinated)),
                isVaccinated, // if specified vaccine is not measles, assume we have measles vaccination
	)

        api.AssertIsEqual(measlesVaccinated, isVaccinated)

        // Constraint #2:
        // If travelers who are coming from or going to a country
        // prone to Yellow Fever transmission (ghana),they must be vaccinated against it (YF)

        // Active yellow fever situation, if coming or going to Ghana
        yfActiveCountry :=
                api.And(
                        api.IsZero(api.Cmp(circuit.CountryFrom, frontend.Variable(ghana))),
                        api.IsZero(api.Cmp(circuit.CountryTo, frontend.Variable(ghana))),
                )

        // Check if vaccinated for yellow fever
        // if both yellowFever and has been vaccinated: is_zero(0) && is_zero(0) => 1 && 1 => 1, else 0
        yfActiveVaccine := api.And(
                api.IsZero(api.Cmp(circuit.VaccineType, frontend.Variable(yellowFever))),
                api.IsZero(api.Cmp(circuit.VaccinatedSecret, isVaccinated)),
        )

        // if the travel routes are to / fro ghana and there's no record of yf vaccination mark as risk
        // if active is true && no active yf vaccine => yellow fever risk
        yfRisk := api.Select(yfActiveCountry, api.IsZero(yfActiveVaccine), noRisk)
        api.AssertIsEqual(yfRisk, noRisk)

        // Constraint #3:
        // Verify the person is of traveling age
        api.AssertIsLessOrEqual(circuit.Age, frontend.Variable(100))

        // Constraint #4:
	// Verify that vaccineType is "measles", or "yellow fever"
        api.AssertIsLessOrEqual(circuit.VaccineType, frontend.Variable(yellowFever))

        // Constraint #5:
        // If vaccine expiration time is not zero time and is less than now, denote that vaccine is not valid
        curTime := time.Now().Unix()

        // If expTime != t.empty() && expTime < time.now() => invalid vaccine
        vaccineInvalid := api.And(
                // If empty/zero time --> outcome is 0, else 1
                // If outcome is 0, vaccineInvalid is automatically 0 or (valid)
                api.Cmp(circuit.VaccineExpDate, frontend.Variable(0)),
                api.IsZero(
                        api.Add(
                                api.Cmp(circuit.VaccineExpDate, frontend.Variable(curTime)),
                                frontend.Variable(1),
                        ),
                ),
                // Add clause #2
                // cmp: i2 is curTime
                // cmp: if i1 < i2 => -1, with +1 => 0, else i1 > i2 => 1, then with +1 => 2, else else i1 == i2 => 0, w/ +1 => 1
                // cmp: if outcome is 0, i1 < i2 or expDate < curTime, so invalid or 1
        )

        // Fail if values are the same, if vaccine is indeed invalid (1)
        // Since it is past due expiration date
        api.AssertIsDifferent(vaccineInvalid, isVaccinated)

        // hash mrn
        mi, _ := mimc.NewMiMC(api)
        mi.Write(circuit.MedicalRecordNum)
	sum := mi.Sum()
	api.AssertIsEqual(circuit.MedicalRecordHash, sum)

	return nil
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

        dob, err := time.Parse(dateFormat, patientData.Dob) // string to time conv
        if err != nil {
                log.Fatal("Error parsing date:", err)
        }

        // Simulate age based on date of birth (for simplicity)
        age := int64(time.Since(dob).Hours()) / 24 / 365 // Approximate age in years

        vExp, err := time.Parse(dateFormat, vaccineData.ExpDate) // string to time conv
        if err != nil {
                log.Fatal("Error parsing date:", err)
        }

        lot, _ := strconv.Atoi(vaccineData.LotNumber)
        mrn, _ := strconv.Atoi(patientData.MedicalRecordNum)

        from := rand.Intn(3) // 0 - ghana, 1 sriLanka - 2 japan
        target := rand.Intn(3)

        // ensure from and target countries are different
        for from == target {
                target = rand.Intn(3)
        }

        vacIndex := rand.Intn(6)
        vacValues := [6]int{1, 1, 2, 2, 1, 1} // 2/3 vac, 1/3 not vac
        vac := vacValues[vacIndex]

        vacType := rand.Intn(2)

        expTime := vExp.Unix() * (int64(rand.Intn(3)) + int64(1)) // scale it up to have a slightly bigger number

        if vac != vaccinated {
                expTime = 0 // since never vaccinated, reset exp date to zero
        }

        if vac != vaccinated && vacType == measles {
                log.Println("Not Vaccinated for Measles")
        }

        if (from == ghana || target == ghana ) && vac != vaccinated && vacType == yellowFever {
                log.Println("NO YellowFever Vaccination and Yellow Fever Area")
        }

        if expTime < time.Now().Unix() && expTime > 0 {
                log.Println("Vaccine expiration time has expired!")
        }

        gen := VaccineCircuit{
                Age:              age,
                VaccineType:      vacType, // ignore faker generated data
                LotNumber:        lot,
                Dob:              dob.Unix(),
                MedicalRecordNum: mrn,
                MedicalRecordHash: hash(mrn),
                CountryFrom:      from,
                CountryTo:    target,
                VaccinatedSecret: vac,
                VaccineExpDate: expTime,
        }

        log.Printf("Generated circuit variables %+v\n", &gen)
        return gen, true
}

// Private helper to retrieve mimc value w/o need for frontend api
func hash(data int) []byte {
	var bigInt = big.NewInt(int64(data))
	var bytes = bigInt.Bytes()

	mc := mimc2.NewMiMC()
	mc.Write(bytes)

	hash := mc.Sum(nil)

	return hash
}
