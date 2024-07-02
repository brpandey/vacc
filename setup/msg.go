package setup

type ProofRequest struct {
	Proof         []byte `json:"proof"`
	PublicWitness []byte `json:"public_witness"`
}

const MsgSubject = "vaccine.proof"
