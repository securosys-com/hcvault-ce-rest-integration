package http

import (
	"errors"
	"fmt"
	"net/http"

	"securosys.ch/hsm"

	"github.com/hashicorp/vault/vault"
)

func handleSysUpdatePolicyHSM(core *vault.Core) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "PUT", "POST":
			handleSysUpdatePolicyHSMPut(core, w, r)
		default:
			respondError(w, http.StatusMethodNotAllowed, nil)
		}
	})
}

func handleSysUpdatePolicyHSMPut(core *vault.Core, w http.ResponseWriter, r *http.Request) {
	configHSM := hsm.InitConfig(false)
	tsb := &hsm.TSBClient{
		Config: &configHSM,
	}

	sealed := core.Sealed()

	if sealed {
		hsm.Logs.UI.Error(fmt.Sprintf("Vault will not be sealed"))
		error := errors.New("Vault will not be sealed!")
		respondError(w, http.StatusForbidden, error)
		return
	}

	// Parse the request
	var req UpdatePolicyHSMRequest
	if _, err := parseJSONRequest(core.PerfStandby(), r, w, &req); err != nil {
		respondError(w, http.StatusBadRequest, err)
		return
	}

	resp := &UpdatePolicyHSMResponse{}
	var policy map[string]string
	policy = req.Policy
	if req.DisablePolicy {
		policy = nil
	}
	err, body, code := tsb.ModifyRSA(configHSM.Key.RSALabel, configHSM.Key.RSAPassword, policy)
	if code == 200 {
		resp.Status = "OK"
		resp.Error = err
		respondOk(w, resp)
		return
	}
	w.Write(body)
	respondError(w, code, err)
}

type UpdatePolicyHSMRequest struct {
	DisablePolicy bool              `json:"disable"`
	Policy        map[string]string `json:"policy"`
}

type UpdatePolicyHSMResponse struct {
	Status string `json:"status"`
	Error  error  `json:"error"`
}
