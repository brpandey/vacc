# Travel vaccines

![ECC](https://github.com/brpandey/vacc/blob/main/ecc.jpg?raw=true)

> Zero knowledge Proofs using Gnark, Golang, ECC BN254 and Nats for messaging between provers and verifier

> Illustrates travel vaccine verification uisng multiple prover workers to generate proofs
> and verify them by a verifier without leaking any sensitive personal data

![WALDO](https://github.com/brpandey/vacc/blob/main/waldo.jpeg?raw=true)

```go
# Prover

$ go run prover.go 
16:07:37 INF compiling circuit
16:07:37 INF parsed circuit inputs nbPublic=5 nbSecret=5
16:07:37 INF building constraint builder nbConstraints=29998
2024/07/03 16:08:00 Generated circuit variables &{Age:6 VaccineType:1 LotNumber:3548539675025022 Dob:1528329600 MedicalRecordNum:3558008676398087 MedicalRecordHash:[4 175 231 199 184 37 92 5 245 141 138 142 146 212 50 42 57 8 94 216 52 46 121 70 40 195 110 56 183 2 67 175] CountryFrom:0 CountryTo:1 VaccinatedSecret:1 VaccineExpDate:4941907200}
16:08:00 DBG constraint system solver done nbConstraints=29998 took=39.679572
16:08:01 DBG prover done acceleration=none backend=groth16 curve=bn254 nbConstraints=29998 took=847.634652
Proof sent successfully

2024/07/03 16:08:06 Vaccine expiration time has expired!
2024/07/03 16:08:06 Generated circuit variables &{Age:41 VaccineType:1 LotNumber:3528250638415605 Dob:412041600 MedicalRecordNum:3588510416991014 MedicalRecordHash:[12 10 97 59 218 83 125 29 206 161 163 184 27 227 14 152 83 53 229 203 93 123 129 174 32 0 145 204 209 156 108 158] CountryFrom:2 CountryTo:0 VaccinatedSecret:1 VaccineExpDate:1619740800}
16:08:06 ERR error="constraint #29666 is not satisfied: 0 ⋅ 0 != 1" nbConstraints=29998
2024/07/03 16:08:06 Unable to create valid proof, since constraints not met: constraint #29666 is not satisfied: 0 ⋅ 0 != 1

2024/07/03 16:08:11 Vaccine expiration time has expired!
2024/07/03 16:08:11 Generated circuit variables &{Age:40 VaccineType:1 LotNumber:3528050902294490 Dob:442540800 MedicalRecordNum:3578238298525846 MedicalRecordHash:[30 103 206 102 55 183 23 253 90 174 165 196 45 159 97 150 225 171 252 232 170 65 84 90 110 63 254 113 127 58 30 216] CountryFrom:1 CountryTo:2 VaccinatedSecret:1 VaccineExpDate:668390400}
16:08:11 ERR error="constraint #29666 is not satisfied: 0 ⋅ 0 != 1" nbConstraints=29998
2024/07/03 16:08:11 Unable to create valid proof, since constraints not met: constraint #29666 is not satisfied: 0 ⋅ 0 != 1

2024/07/03 16:08:16 Generated circuit variables &{Age:51 VaccineType:1 LotNumber:3568086344271599 Dob:105321600 MedicalRecordNum:3558793954915690 MedicalRecordHash:[9 107 17 91 177 191 108 87 172 80 122 188 133 14 65 177 247 199 186 157 85 66 207 128 27 177 247 155 233 219 227 253] CountryFrom:2 CountryTo:1 VaccinatedSecret:2 VaccineExpDate:0}
16:08:16 DBG constraint system solver done nbConstraints=29998 took=42.230534
16:08:17 DBG prover done acceleration=none backend=groth16 curve=bn254 nbConstraints=29998 took=851.085285
Proof sent successfully

2024/07/03 16:08:22 Vaccine expiration time has expired!
2024/07/03 16:08:22 Generated circuit variables &{Age:52 VaccineType:1 LotNumber:3548421592885792 Dob:64022400 MedicalRecordNum:3548294835230835 MedicalRecordHash:[40 246 21 122 85 111 205 80 52 216 86 40 79 230 36 122 45 77 19 95 30 10 190 19 161 29 111 65 41 241 48 232] CountryFrom:0 CountryTo:2 VaccinatedSecret:1 VaccineExpDate:1399852800}
16:08:22 ERR error="constraint #29666 is not satisfied: 0 ⋅ 0 != 1" nbConstraints=29998
2024/07/03 16:08:22 Unable to create valid proof, since constraints not met: constraint #29666 is not satisfied: 0 ⋅ 0 != 1

2024/07/03 16:08:27 NO YellowFever Vaccination and Yellow Fever Area
2024/07/03 16:08:27 Generated circuit variables &{Age:46 VaccineType:1 LotNumber:3538173771564262 Dob:248140800 MedicalRecordNum:3588954891235229 MedicalRecordHash:[6 160 249 227 7 134 11 47 170 224 164 38 135 71 28 54 66 12 47 128 79 85 172 190 84 114 17 72 46 247 245 51] CountryFrom:1 CountryTo:0 VaccinatedSecret:2 VaccineExpDate:0}
16:08:27 DBG constraint system solver done nbConstraints=29998 took=42.682695
16:08:28 DBG prover done acceleration=none backend=groth16 curve=bn254 nbConstraints=29998 took=889.820438
Proof sent successfully

2024/07/03 16:08:33 Vaccine expiration time has expired!
2024/07/03 16:08:33 Generated circuit variables &{Age:22 VaccineType:0 LotNumber:3538016561847154 Dob:1010102400 MedicalRecordNum:3548949187923884 MedicalRecordHash:[32 49 195 37 61 158 154 36 37 4 44 133 126 233 82 234 37 230 192 90 192 141 226 176 50 231 181 173 213 213 37 95] CountryFrom:0 CountryTo:2 VaccinatedSecret:1 VaccineExpDate:650764800}
16:08:33 ERR error="constraint #29666 is not satisfied: 0 ⋅ 0 != 1" nbConstraints=29998
2024/07/03 16:08:33 Unable to create valid proof, since constraints not met: constraint #29666 is not satisfied: 0 ⋅ 0 != 1

2024/07/03 16:08:38 NO YellowFever Vaccination and Yellow Fever Area
2024/07/03 16:08:38 Generated circuit variables &{Age:27 VaccineType:1 LotNumber:3558065434408548 Dob:857520000 MedicalRecordNum:3558269649739911 MedicalRecordHash:[4 63 84 136 246 36 249 247 244 186 69 95 54 145 114 92 119 105 139 141 74 234 132 27 45 237 222 87 87 252 43 126] CountryFrom:2 CountryTo:0 VaccinatedSecret:2 VaccineExpDate:0}
16:08:38 DBG constraint system solver done nbConstraints=29998 took=50.343945
16:08:39 DBG prover done acceleration=none backend=groth16 curve=bn254 nbConstraints=29998 took=885.170638
Proof sent successfully

```


```go
# Verifier

$ go run verifier.go 
Awaiting vaccine proofs to be verified 
16:08:01 DBG verifier done backend=groth16 curve=bn254 took=6.195128
Proof verified successfully, patient passed vaccine authentication

16:08:17 DBG verifier done backend=groth16 curve=bn254 took=4.3031
Proof verified successfully, patient passed vaccine authentication

16:08:28 DBG verifier done backend=groth16 curve=bn254 took=3.826664
Proof verified successfully, patient passed vaccine authentication

16:08:39 DBG verifier done backend=groth16 curve=bn254 took=4.183551
Proof verified successfully, patient passed vaccine authentication
```
