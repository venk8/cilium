// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package validator

import (
	"fmt"
	"log/slog"

	apiextensionsinternal "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	"k8s.io/apiextensions-apiserver/pkg/apiserver/validation"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/cilium/cilium/pkg/k8s/apis/cilium.io/client"
)

// NPValidator is a validator structure used to validate CNP and CCNP.
type NPValidator struct {
	logger        *slog.Logger
	cnpValidator  validation.SchemaCreateValidator
	ccnpValidator validation.SchemaCreateValidator
}

func compileSchemaValidator(crv *apiextensionsv1.CustomResourceValidation) (validation.SchemaCreateValidator, error) {
	if crv == nil {
		return nil, fmt.Errorf("schema validation is nil")
	}
	var internal apiextensionsinternal.CustomResourceValidation
	if err := apiextensionsv1.Convert_v1_CustomResourceValidation_To_apiextensions_CustomResourceValidation(
		crv,
		&internal,
		nil,
	); err != nil {
		return nil, err
	}
	validator, _, err := validation.NewSchemaValidator(internal.OpenAPIV3Schema)
	if err != nil {
		return nil, err
	}
	return validator, nil
}

func NewNPValidator(logger *slog.Logger) (*NPValidator, error) {
	cnpCRD := client.GetPregeneratedCRD(logger, client.CNPCRDName)
	if len(cnpCRD.Spec.Versions) == 0 {
		return nil, fmt.Errorf("no versions found for CRD %s", client.CNPCRDName)
	}
	cnpValidator, err := compileSchemaValidator(cnpCRD.Spec.Versions[0].Schema)
	if err != nil {
		return nil, err
	}

	ccnpCRD := client.GetPregeneratedCRD(logger, client.CCNPCRDName)
	if len(ccnpCRD.Spec.Versions) == 0 {
		return nil, fmt.Errorf("no versions found for CRD %s", client.CCNPCRDName)
	}
	ccnpValidator, err := compileSchemaValidator(ccnpCRD.Spec.Versions[0].Schema)
	if err != nil {
		return nil, err
	}

	return &NPValidator{
		logger:        logger,
		cnpValidator:  cnpValidator,
		ccnpValidator: ccnpValidator,
	}, nil
}

// ValidateCNP validates the given CNP accordingly the CNP validation schema.
func (n *NPValidator) ValidateCNP(cnp *unstructured.Unstructured) error {
	if errs := validation.ValidateCustomResource(nil, &cnp, n.cnpValidator); len(errs) > 0 {
		return errs.ToAggregate()
	}

	if err := detectUnknownFields(n.logger, cnp); err != nil {
		return err
	}

	return nil
}

// ValidateCCNP validates the given CCNP accordingly the CCNP validation schema.
func (n *NPValidator) ValidateCCNP(ccnp *unstructured.Unstructured) error {
	if errs := validation.ValidateCustomResource(nil, &ccnp, n.ccnpValidator); len(errs) > 0 {
		return errs.ToAggregate()
	}

	if err := detectUnknownFields(n.logger, ccnp); err != nil {
		return err
	}

	return nil
}
