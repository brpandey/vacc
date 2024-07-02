package msg

import (
        "github.com/consensys/gnark/backend/groth16"
        "github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark-crypto/ecc"

        "log"
        "encoding/json"
        "bytes"
)

type ProofRequest struct {
	Proof         []byte `json:"proof"`
	PublicWitness []byte `json:"public_witness"`
}

const Subject = "vaccine.proof"

func NewRequest(proof groth16.Proof, publicWitness witness.Witness) ProofRequest {
        var proofBuf, witnessBuf bytes.Buffer

        proof.WriteRawTo(&proofBuf)
        publicWitness.WriteTo(&witnessBuf)

        // Create proof request
        request := ProofRequest{
                Proof:         proofBuf.Bytes(),
                PublicWitness: witnessBuf.Bytes(),
        }

        return request
}

func Serialize(request ProofRequest) []byte {
        req, err := json.Marshal(request)

        if err != nil {
                log.Fatal("Error marshalling request:", err)
        }

        return req
}

func Deserialize(data []byte) (groth16.Proof, witness.Witness) {
        var proofRequest ProofRequest
        if err := json.Unmarshal(data, &proofRequest); err != nil {
                log.Fatal("Error decoding proof request:", err)
        }

        // Unmarshal proof
        proof := groth16.NewProof(ecc.BN254)
        witness, _ := witness.New(ecc.BN254.ScalarField())

        proof.ReadFrom(bytes.NewBuffer(proofRequest.Proof))
        witness.ReadFrom(bytes.NewBuffer(proofRequest.PublicWitness))

        return proof, witness
}
