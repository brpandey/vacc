# Travel vaccine
## Vaccine verification using ZK Proofs

![WALDO](https://github.com/brpandey/vacc/blob/main/waldo.jpeg?raw=true)


> Zero knowledge Proofs using Gnark, Golang, ECC BN254 and Nats for messaging between provers and verifier

![ECC](https://github.com/brpandey/vacc/blob/main/ecc.jpg?raw=true)

> Illustrates travel vaccine verification uisng multiple prover workers to generate proofs
> and verify them by a verifier without leaking any sensitive personal data

```rust
// Construct circuit's constraints
func (circuit *VaccineCircuit) Define(api frontend.API) error {
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
```


```haskell
# See prover.log

2024/07/04 18:53:34 [NEW] traveler &{Age:43 VaccineType:1 LotNumber:376503936263800 Dob:339120000 MedicalRecordNum:343664090834775 MedicalRecordHash:[1 122 128 147 216 145 131 178 86 107 176 131 29 150 250 70 40 110 25 192 65 198 185 220 200 200 184 44 178 163 125 106] CountryFrom:1 CountryTo:2 VaccinatedSecret:0 VaccineExpDate:0}
18:53:34 DBG constraint system solver done nbConstraints=33556 took=57.245394
18:53:35 DBG prover done acceleration=none backend=groth16 curve=bn254 nbConstraints=33556 took=1675.115905
[OK] Proof sent successfully

2024/07/04 18:53:39 [!!] Vaccine expiration time has expired!
2024/07/04 18:53:39 [NEW] traveler &{Age:10 VaccineType:1 LotNumber:348367540237593 Dob:1389571200 MedicalRecordNum:376894624500803 MedicalRecordHash:[39 75 3 159 205 21 223 79 60 185 2 252 222 27 60 204 200 171 178 228 211 246 210 200 208 155 87 158 142 77 51 135] CountryFrom:2 CountryTo:0 VaccinatedSecret:1 VaccineExpDate:1645574400}
18:53:39 ERR error="constraint #33224 is not satisfied: 1 ⋅ 1 != 0" nbConstraints=33556
2024/07/04 18:53:39 [X] Constraints not met, unable to create valid proof: constraint #33224 is not satisfied: 1 ⋅ 1 != 0

2024/07/04 18:53:44 [!!] No YellowFever Vaccination and from/to Yellow Fever Area
2024/07/04 18:53:44 [NEW] traveler &{Age:45 VaccineType:1 LotNumber:371864288485165 Dob:270345600 MedicalRecordNum:373531245071625 MedicalRecordHash:[0 245 28 207 54 75 10 252 120 198 56 69 167 141 70 43 255 166 168 237 249 238 123 111 99 236 203 176 84 6 113 104] CountryFrom:0 CountryTo:1 VaccinatedSecret:0 VaccineExpDate:0}
18:53:44 ERR error="constraint #21339 is not satisfied: 1 ⋅ 1 != 0" nbConstraints=33556
2024/07/04 18:53:44 [X] Constraints not met, unable to create valid proof: constraint #21339 is not satisfied: 1 ⋅ 1 != 0
```


```haskell
# See verifier.log

18:53:35 DBG verifier done backend=groth16 curve=bn254 took=7.896169
[Ok] Proof verified successfully, traveler passed authentication
```
