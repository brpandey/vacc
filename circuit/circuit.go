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
        yellowFever //https://wwwnc.cdc.gov/travel/yellowbook/2024/infections-diseases/yellow-fever
)

const (
	notVaccinated = iota
	vaccinated
)

const (
	ghana = iota // https://wwwnc.cdc.gov/travel/destinations/traveler/none/ghana
	sriLanka // https://wwwnc.cdc.gov/travel/destinations/traveler/none/sri-lanka
        japan
)

const dateFormat = "2006-01-02"

// Define fake vaccine data and patient data schema
type VaccineData struct {
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
        // Note: Defining a variable like one := frontend.Variable(1),
        // to reuse throughout code doesn't work => will see unsolved errors

        // Note: Cmp returns 1 if i1>i2, 0 if i1=i2, -1 if i1<i2
        meVaccineType := api.IsZero(api.Cmp(circuit.VaccineType, frontend.Variable(measles)))
        api.AssertIsBoolean(meVaccineType)

        // Constraint #1: if type is measles, must be vaccinated for it
        // if specified vaccine is not measles, assume successful measles vaccination
	measlesVaccinated := api.Select(
                meVaccineType,
                api.IsZero(api.Cmp(frontend.Variable(1), circuit.VaccinatedSecret)), // is vaccinated?
                frontend.Variable(1),
        )

        api.AssertIsBoolean(measlesVaccinated)
        api.AssertIsEqual(measlesVaccinated, frontend.Variable(1))

        // Constraint #2:
        // If travelers who are coming from or going to a country
        // prone to Yellow Fever transmission (ghana), they must be vaccinated against YF

        // Active yellow fever situation, if coming or going to Ghana, and if vaccineType is yellowFever
        // if vaccineType is not yellowFever, assume active country status is irrelevant or 0..
        yfVaccineType := api.IsZero(api.Cmp(circuit.VaccineType, frontend.Variable(yellowFever)))
        yfActiveCountry :=
                api.And(
                        api.Or( // countries: ghana 0, sriLanka 1, japan 2
                                api.IsZero(api.Cmp(circuit.CountryFrom, frontend.Variable(ghana))),
                                api.IsZero(api.Cmp(circuit.CountryTo, frontend.Variable(ghana))),
                        ),
                        yfVaccineType,
                )

        // Check if vaccinated for yellow fever
        yfActiveVaccine := api.IsZero(api.Cmp(frontend.Variable(1), circuit.VaccinatedSecret))

        // if the travel routes are to / from ghana and there's no record of yf vaccination mark as risk
        // if active is true && no active yf vaccine => yellow fever risk

        yfRisk := api.Select(yfActiveCountry, api.IsZero(yfActiveVaccine), frontend.Variable(0))
        api.AssertIsBoolean(yfRisk)
        api.AssertIsEqual(yfRisk, frontend.Variable(0))

        // Constraint #3:
        // Verify the person is of traveling age
        api.AssertIsLessOrEqual(circuit.Age, frontend.Variable(100))

        // Constraint #4:
	// Verify that vaccineType is "measles", or "yellow fever"
        api.AssertIsLessOrEqual(circuit.VaccineType, frontend.Variable(yellowFever))

        // Constraint #5:
        // If vaccine expiration time is not zero time and is less than now, denote that vaccine is not valid
        curTime := time.Now().Unix()

        // if never vaccinated, time will be 0, expired status only applies to if was previously vaccinated
        // If expTime != t.empty() && expTime < time.now() => invalid vaccine
        vaccineExpired := api.And(
                // If empty/zero time --> outcome is 0, else 1
                // If outcome is 0, vaccineExpired is automatically 0 or (valid)
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

        // safeguard, vaccine expired state matters only if vaccinated
        vaccineExpired = api.And(
                vaccineExpired,
                api.IsZero(api.Cmp(frontend.Variable(1), circuit.VaccinatedSecret)))

        // Fail if values are the same, if vaccine is indeed invalid (1)
        // Since it is past due expiration date
        api.AssertIsEqual(vaccineExpired, frontend.Variable(0))

        // hash mrn
        mi, _ := mimc.NewMiMC(api)
        mi.Write(circuit.MedicalRecordNum)
	sum := mi.Sum()
	api.AssertIsEqual(circuit.MedicalRecordHash, sum)

	return nil
}

// Generate vaccine circuit fields using faker library
func Generate() (VaccineCircuit, bool) {
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

        index := rand.Intn(6) // use to drive weighted values

        vacValues := [6]int{1, 1, 0, 1, 1, 1} // 5/6 vac, 1/6 not vac
        vac := vacValues[index]

        vacType := rand.Intn(2)

        // scale it up to have a slightly bigger number => to avoid too many expired vaccine dates
        expTime := vExp.Unix() * (int64(rand.Intn(3)) + int64(2))
        factorValues := [6]int{1, 1, 0, 0, 1, 1}

        expTime = expTime + time.Now().Unix()*int64(factorValues[index]) // 1/3 chance we don't add to current time

        if vac != vaccinated {
                expTime = 0 // since never vaccinated, reset exp date to zero
        }

        if vac != vaccinated && vacType == measles {
                log.Println("[!!] Not Vaccinated for Measles")
        }

        if (from == ghana || target == ghana ) && vac != vaccinated && vacType == yellowFever {
                log.Println("[!!] No YellowFever Vaccination and from/to Yellow Fever Area")
        }

        if expTime < time.Now().Unix() && expTime > 0 {
                log.Println("[!!] Vaccine expiration time has expired!")
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

        log.Printf("[NEW] traveler %+v\n", &gen)
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
